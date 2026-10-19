import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from collections import Counter
from datetime import date, datetime, timedelta
from pathlib import PurePosixPath
from typing import Annotated, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, FastAPI, File, Form, Query, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError, model_validator
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware

from admin_diagnostics import gateway_metadata
from auth import new_token, password_hash, token_hash, verify_password
from body_limit import BodyLimitMiddleware
from config import Settings
from detector import TYPES, scan, scan_file
from errors import APIError
from intent import interpret
from multipart_memory import MemoryUploadRoute
from sanitizer import decode_text, sanitize
from schemas import (
    AssistInput,
    AssistResult,
    FileScanResult,
    LogInput,
    SanitizeAction,
    SanitizeResult,
    ScanInput,
    ScanResult,
)
from storage import Storage, qr_data
from store import Store, now

SCAN_EXTENSIONS = {".txt", ".csv"}
ALLOWED_EXTENSIONS = SCAN_EXTENSIONS | {
    ".json",
    ".md",
    ".log",
    ".xml",
    ".yaml",
    ".yml",
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
}
logger = logging.getLogger("securedrop")
logger.setLevel(logging.INFO)


class FileMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=255)
    size: int = Field(strict=True, ge=1)
    type: str = Field(
        default="application/octet-stream",
        min_length=1,
        max_length=128,
        pattern=r"^[\w.+-]+/[\w.+-]+$",
    )
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    scan_id: str | None = Field(default=None, max_length=64)
    sanitize_id: str | None = Field(default=None, max_length=64)


class TransferInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    files: list[FileMetadata] = Field(min_length=1, max_length=5)
    scan_id: str | None = Field(default=None, max_length=64)
    sanitize_id: str | None = Field(default=None, max_length=64)
    expires_in: int | None = None
    encrypted: bool = False
    acknowledge_risk: bool = False
    acknowledge_unsupported: bool = False
    user_approved: bool = False

    @model_validator(mode="after")
    def validate_references(self):
        if (self.scan_id and self.sanitize_id) or (
            len(self.files) != 1 and (self.scan_id or self.sanitize_id)
        ):
            raise ValueError("Use one reference per file")
        for item in self.files:
            refs = [item.scan_id, item.sanitize_id, self.scan_id, self.sanitize_id]
            if sum(bool(ref) for ref in refs) > 1:
                raise ValueError("Use one reference per file")
        return self


class LoginInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=1024)


class PluginTextInput(ScanInput):
    expires_in: int | None = None
    user_approved: bool = False


def validate_filename(filename, allowed=ALLOWED_EXTENSIONS):
    filename = PurePosixPath((filename or "").replace("\\", "/")).name
    extension = PurePosixPath(filename).suffix.lower()
    if extension not in allowed or len(filename) > 255 or any(ord(c) < 32 for c in filename):
        status = 415 if allowed == SCAN_EXTENSIONS else 422
        raise APIError(
            status,
            "UNSUPPORTED_TYPE" if status == 415 else "VALIDATION_ERROR",
            "허용되지 않는 파일 형식입니다.",
        )
    return filename, extension


def create_app(settings: Settings | None = None, storage=None, store=None):
    settings = settings or Settings()
    store = store or Store(settings)
    storage = storage or Storage(settings)
    app = FastAPI(
        title="SecureDrop Cloud",
        version="1.3.0",
        root_path=settings.root_path,
        middleware=[
            Middleware(
                CORSMiddleware,
                allow_origins=settings.allowed_origins,
                allow_methods=["GET", "POST", "DELETE"],
                allow_headers=[
                    "Content-Type",
                    "X-API-Key",
                    "X-Source",
                    "X-Manage-Token",
                    "Authorization",
                ],
            ),
            Middleware(
                BodyLimitMiddleware,
                limit=settings.scan_file_max_mb * 1024 * 1024 + 65536,
                scan_limit=settings.scan_file_max_mb * 1024 * 1024 + 65536,
            ),
        ],
    )
    app.router.route_class = MemoryUploadRoute
    app.state.store, app.state.storage, app.state.settings = store, storage, settings

    @app.exception_handler(APIError)
    async def api_error(request, exc):
        return JSONResponse(
            {"error": {"code": exc.code, "message": exc.message}}, status_code=exc.status
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return JSONResponse(
            {
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "요청 형식이나 입력값을 확인하세요.",
                }
            },
            status_code=422,
        )

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        return JSONResponse(
            {
                "error": {
                    "code": "NOT_FOUND" if exc.status_code == 404 else "VALIDATION_ERROR",
                    "message": "요청을 처리할 수 없습니다.",
                }
            },
            status_code=exc.status_code,
        )

    @app.exception_handler(Exception)
    async def internal_error(request, exc):
        return JSONResponse(
            {
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "서버에서 요청을 처리하지 못했습니다.",
                }
            },
            status_code=500,
        )

    @app.middleware("http")
    async def privacy_headers(request, call_next):
        request.state.request_id = uuid4().hex
        start = time.monotonic()
        if request.url.path.startswith("/api/admin/"):
            logger.info(
                json.dumps(
                    {
                        "event": "admin_asgi_received",
                        **gateway_metadata(request.scope.get("aws.event", {})),
                        "request_id": request.state.request_id,
                        "authorization_present": "authorization" in request.headers,
                    }
                )
            )
        response = await call_next(request)
        response.headers.update(
            {
                "Cache-Control": "no-store",
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
            }
        )
        route = request.scope.get("route")
        # Route templates avoid logging transfer IDs, tokens, queries or user input.
        logger.info(
            json.dumps(
                {
                    "request_id": request.state.request_id,
                    "path": getattr(route, "path", "unmatched"),
                    "status": response.status_code,
                    "latency_ms": round((time.monotonic() - start) * 1000),
                    "gateway_request_id": request.scope.get("aws.event", {})
                    .get("requestContext", {})
                    .get("requestId"),
                }
            )
        )
        return response

    def event(request, kind, types, source="web"):
        store.log(kind, types, source, request.state.request_id)
        metrics = {"BLOCK": "BlockedCount", "TRANSFER": "TransferCount"}
        if kind in metrics:
            metric = metrics[kind]
            for detection in sorted(set(types)) or ["NONE"]:
                logger.info(
                    json.dumps(
                        {
                            "_aws": {
                                "Timestamp": int(time.time() * 1000),
                                "CloudWatchMetrics": [
                                    {
                                        "Namespace": "SecureDrop",
                                        "Dimensions": [["Type", "Source"]],
                                        "Metrics": [{"Name": metric, "Unit": "Count"}],
                                    }
                                ],
                            },
                            "Type": detection,
                            "Source": source,
                            metric: 1,
                            "request_id": request.state.request_id,
                            "event": kind,
                        }
                    )
                )

    def expires(value):
        value = settings.default_expires_sec if value is None else value
        if value not in (300, 600, 3600) or value > settings.max_expires_sec:
            raise APIError(422, "VALIDATION_ERROR", "만료 시간은 300, 600, 3600초 중 선택하세요.")
        return value

    async def read_file(file):
        content = await file.read(settings.scan_file_max_mb * 1024 * 1024 + 1)
        if len(content) > settings.scan_file_max_mb * 1024 * 1024:
            raise APIError(413, "FILE_TOO_LARGE", "파일은 최대 4MiB입니다.")
        if not content:
            raise APIError(422, "VALIDATION_ERROR", "빈 파일은 처리할 수 없습니다.")
        return content

    def save_session(kind, content, result):
        identifier = secrets.token_hex(16)
        digest = hashlib.sha256(content).hexdigest()
        deadline = now() + timedelta(seconds=settings.session_ttl_sec)
        store.put(
            "sessions",
            {
                "session_id": identifier,
                "kind": kind,
                "sha256": digest,
                "findings": result["findings"],
                "clean": not result["blocked"],
                "supported": True,
                "expires_at": deadline.isoformat(),
                "ttl": int(deadline.timestamp()),
            },
        )
        return identifier, digest

    def get_session(identifier, kind):
        row = store.get("sessions", {"session_id": identifier})
        if (
            not row
            or int(row["ttl"]) <= int(now().timestamp())
            or datetime.fromisoformat(row["expires_at"]) <= now()
        ):
            raise APIError(410, "EXPIRED", "검사·정제 세션이 만료되었습니다.")
        if row["kind"] != kind:
            raise APIError(422, "VALIDATION_ERROR", "검사·정제 참조가 올바르지 않습니다.")
        return row

    def get_transfer(identifier, request=None, active=False):
        row = store.transfer(identifier)
        if not row:
            raise APIError(404, "NOT_FOUND", "전송을 찾을 수 없습니다.")
        if request is not None and not hmac.compare_digest(
            row["manage_hash"], token_hash(request.headers.get("X-Manage-Token", ""))
        ):
            raise APIError(403, "FORBIDDEN", "해당 전송의 관리 토큰이 필요합니다.")
        if row["status"] == "REVOKED":
            raise APIError(404, "NOT_FOUND", "전송을 찾을 수 없습니다.")
        if active:
            if datetime.fromisoformat(row["expires_at"]) <= now():
                raise APIError(410, "EXPIRED", "만료된 전송입니다.")
            if row["status"] != "ACTIVE":
                raise APIError(409, "UPLOAD_INCOMPLETE", "업로드가 완료되지 않았습니다.")
        return row

    def public_status(row):
        return {
            "id": row["transfer_id"],
            "status": row["status"],
            "expires_at": row["expires_at"],
            "download_count": int(row["download_count"]),
        }

    def share(row, request):
        base = str(settings.public_base_url or request.base_url).rstrip("/")
        url = f"{base}/d.html?id={row['transfer_id']}"
        return {**public_status(row), "share_url": url, "qr": qr_data(url)}

    def revoke(row, request, source):
        # Revoke first: a concurrent /complete may never reactivate the record.
        if row["status"] != "REVOKED":
            store.transition(row["transfer_id"], row["status"], "REVOKED")
            event(request, "REVOKE", [], source)
        for item in row["files"]:
            storage.delete(item["s3_key"])
        return {"id": row["transfer_id"], "status": "REVOKED"}

    @app.get("/api/health")
    def health():
        return {"status": "ok", "region": settings.aws_region}

    @app.post("/api/scan", response_model=ScanResult)
    def scan_text(payload: ScanInput, request: Request):
        result = scan(payload.text)
        event(request, "SCAN", [f["type"] for f in result["findings"]])
        return result

    @app.post("/api/scan/file", response_model=FileScanResult)
    async def scan_uploaded_file(request: Request, file: Annotated[UploadFile, File()]):
        try:
            filename, _ = validate_filename(file.filename, SCAN_EXTENSIONS)
            content = await read_file(file)
            result = await run_in_threadpool(scan_file, decode_text(content))
            identifier, digest = await run_in_threadpool(save_session, "SCAN", content, result)
            await run_in_threadpool(event, request, "SCAN", [f["type"] for f in result["findings"]])
            return {"filename": filename, "scan_id": identifier, "sha256": digest, **result}
        finally:
            await file.close()

    @app.post("/api/assist", response_model=AssistResult)
    def assist(payload: AssistInput):
        return interpret(payload.message, [f.model_dump() for f in payload.context.findings])

    @app.post("/api/sanitize", response_model=SanitizeResult)
    async def sanitize_file(
        request: Request, file: Annotated[UploadFile, File()], actions: Annotated[str, Form()]
    ):
        try:
            validate_filename(file.filename, SCAN_EXTENSIONS)
            try:
                parsed = TypeAdapter(list[SanitizeAction]).validate_json(actions)
            except ValidationError as exc:
                raise APIError(422, "VALIDATION_ERROR", "정제 조치 형식을 확인하세요.") from exc
            if not parsed or len(parsed) > len(TYPES):
                raise APIError(422, "VALIDATION_ERROR", "정제 조치를 선택하세요.")
            cancelled = any(item.action == "CANCEL" for item in parsed)
            selected = {}
            for item in parsed:
                if (cancelled and (len(parsed) != 1 or item.targets)) or (
                    not cancelled and not item.targets
                ):
                    raise APIError(
                        422, "VALIDATION_ERROR", "취소와 정제 조치를 함께 적용할 수 없습니다."
                    )
                for target in item.targets:
                    if target in selected:
                        raise APIError(422, "VALIDATION_ERROR", "유형별 조치는 하나만 선택하세요.")
                    selected[target] = item.action
            content = await read_file(file)
            text = decode_text(content)
            before = await run_in_threadpool(scan_file, text)
            if cancelled:
                return {
                    "sanitize_id": None,
                    "findings_before": before["findings"],
                    "findings_after": [],
                    "preview": "",
                    "clean": False,
                    "cancelled": True,
                }
            processed = await run_in_threadpool(sanitize, text, selected)
            processed_bytes = processed.encode("utf-8")
            if len(processed_bytes) > settings.scan_file_max_mb * 1024 * 1024:
                raise APIError(413, "FILE_TOO_LARGE", "UTF-8 처리본은 최대 4MiB입니다.")
            after = await run_in_threadpool(scan_file, processed)
            identifier, digest = await run_in_threadpool(
                save_session, "SANITIZE", processed_bytes, after
            )
            await run_in_threadpool(event, request, "SANITIZE", list(selected))
            return {
                "sanitize_id": identifier,
                "sha256": digest,
                "content_b64": base64.b64encode(processed_bytes).decode(),
                "findings_before": before["findings"],
                "findings_after": after["findings"],
                "preview": "\n".join(processed.splitlines()[:20])[:10000],
                "clean": not after["blocked"],
            }
        finally:
            await file.close()

    @app.post("/api/transfers")
    def create_transfer(payload: TransferInput, request: Request):
        duration = expires(payload.expires_in)
        if len(payload.files) > settings.max_files_per_transfer:
            raise APIError(422, "VALIDATION_ERROR", "파일 개수 제한을 초과했습니다.")
        if sum(item.size for item in payload.files) > settings.max_file_mb * 1024 * 1024:
            raise APIError(413, "FILE_TOO_LARGE", "전송 파일은 합계 20MiB 이하여야 합니다.")
        identifier = secrets.token_hex(16)
        items, references = [], []
        for i, item in enumerate(payload.files):
            name, extension = validate_filename(item.name)
            scan_id = item.scan_id or payload.scan_id
            sanitize_id = item.sanitize_id or payload.sanitize_id
            reference = sanitize_id or scan_id
            session = (
                get_session(reference, "SANITIZE" if sanitize_id else "SCAN") if reference else None
            )
            if extension in SCAN_EXTENSIONS:
                if session is None:
                    raise APIError(422, "VALIDATION_ERROR", "검사 또는 정제 참조가 필요합니다.")
            elif not payload.acknowledge_unsupported:
                raise APIError(
                    422, "VALIDATION_ERROR", "검사 미지원 형식에 대한 확인이 필요합니다."
                )
            if sanitize_id and not payload.user_approved:
                raise APIError(422, "VALIDATION_ERROR", "처리본 미리보기 승인이 필요합니다.")
            if session and not session["clean"] and not payload.acknowledge_risk:
                event(request, "BLOCK", [f["type"] for f in session["findings"]])
                raise APIError(
                    409, "SENSITIVE_REMAINS", "민감정보 정제 또는 위험 확인이 필요합니다."
                )
            digest = item.sha256.lower()
            if session and not payload.encrypted and digest != session["sha256"]:
                raise APIError(
                    409, "INTEGRITY_MISMATCH", "검사·정제 결과 해시가 일치하지 않습니다."
                )
            items.append(
                {
                    "name": name,
                    "size": item.size,
                    "type": item.type,
                    "sha256": digest,
                    "s3_key": f"transfers/{identifier}/{i}",
                }
            )
            references.append(reference or "")
        uploads = [storage.upload_post(item) for item in items]
        token, hashed = new_token()
        created = now()
        deadline = created + timedelta(seconds=duration)
        store.put(
            "transfers",
            {
                "transfer_id": identifier,
                "manage_hash": hashed,
                "status": "PENDING_UPLOAD",
                "files": items,
                "encrypted": payload.encrypted,
                "source": "web",
                "scan_ref": references,
                "created_at": created.isoformat(),
                "created_day": created.date().isoformat(),
                "expires_at": deadline.isoformat(),
                "upload_expires_at": (
                    created + timedelta(seconds=settings.upload_url_ttl_sec)
                ).isoformat(),
                "download_count": 0,
                "ttl": int((created + timedelta(hours=1)).timestamp()),
            },
        )
        return {
            "id": identifier,
            "manage_token": token,
            "status": "PENDING_UPLOAD",
            "uploads": uploads,
            "upload_expires_in": settings.upload_url_ttl_sec,
            "expires_at": deadline.isoformat(),
        }

    @app.post("/api/transfers/{identifier}/complete")
    def complete_transfer(identifier: str, request: Request):
        row = get_transfer(identifier, request)
        if datetime.fromisoformat(row["expires_at"]) <= now():
            raise APIError(410, "EXPIRED", "만료된 전송입니다.")
        if row["status"] == "ACTIVE":
            return share(row, request)
        if datetime.fromisoformat(row["upload_expires_at"]) <= now():
            raise APIError(410, "EXPIRED", "업로드 유효 시간이 지났습니다.")
        try:
            for item in row["files"]:
                storage.verify(item)
        except APIError as exc:
            if exc.code == "INTEGRITY_MISMATCH":
                revoke(row, request, row["source"])
            raise
        row = store.transition(
            identifier,
            "PENDING_UPLOAD",
            "ACTIVE",
            ttl=int(datetime.fromisoformat(row["expires_at"]).timestamp()) + 86400,
        )
        event(request, "TRANSFER", [], row["source"])
        return share(row, request)

    @app.get("/api/transfers/{identifier}")
    def transfer_status(identifier: str, request: Request):
        row = get_transfer(identifier, request)
        if datetime.fromisoformat(row["expires_at"]) <= now():
            raise APIError(410, "EXPIRED", "만료된 전송입니다.")
        return public_status(row)

    @app.delete("/api/transfers/{identifier}")
    def revoke_transfer(identifier: str, request: Request):
        # Allow retries after a failed S3 delete, including already revoked rows.
        row = store.transfer(identifier)
        if not row:
            raise APIError(404, "NOT_FOUND", "전송을 찾을 수 없습니다.")
        if not hmac.compare_digest(
            row["manage_hash"], token_hash(request.headers.get("X-Manage-Token", ""))
        ):
            raise APIError(403, "FORBIDDEN", "해당 전송의 관리 토큰이 필요합니다.")
        return revoke(row, request, "web")

    @app.get("/api/d/{identifier}")
    def download_transfer(identifier: str, request: Request):
        row = get_transfer(identifier, active=True)
        remaining = int((datetime.fromisoformat(row["expires_at"]) - now()).total_seconds())
        if remaining < 1:
            raise APIError(410, "EXPIRED", "만료된 전송입니다.")
        files = [
            {
                "name": item["name"],
                "size": int(item["size"]),
                "url": storage.download_url(item, min(settings.download_url_ttl_sec, remaining)),
            }
            for item in row["files"]
        ]
        store.count_download(identifier)
        event(request, "DOWNLOAD", [], row["source"])
        return {"files": files, "encrypted": row["encrypted"], "expires_at": row["expires_at"]}

    @app.post("/api/ext/logs")
    def extension_log(payload: LogInput, request: Request):
        event(request, "BLOCK", payload.types, "extension")
        return {"ok": True}

    bearer = HTTPBearer(auto_error=False)

    def admin_trace(request, stage, **fields):
        logger.info(
            json.dumps(
                {
                    "event": "admin_auth_trace",
                    "stage": stage,
                    "request_id": request.state.request_id,
                    "gateway_request_id": request.scope.get("aws.event", {})
                    .get("requestContext", {})
                    .get("requestId"),
                    **fields,
                }
            )
        )

    def administrator(
        request: Request,
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    ):
        admin_trace(request, "bearer_parsed", credentials_present=credentials is not None)
        row = (
            store.get("admin_sessions", {"token_hash": token_hash(credentials.credentials)})
            if credentials
            else None
        )
        if credentials:
            admin_trace(request, "session_read", session_found=row is not None)
        reason = (
            "credentials_missing_or_invalid"
            if not credentials
            else "session_not_found"
            if not row
            else "session_expired"
            if datetime.fromisoformat(row["expires_at"]) <= now()
            else None
        )
        if reason:
            # Log only failure categories and correlation IDs, never headers or tokens.
            gateway = request.scope.get("aws.event", {}).get("requestContext", {})
            logger.warning(
                json.dumps(
                    {
                        "event": "admin_auth_failed",
                        "reason": reason,
                        "authorization_present": "authorization" in request.headers,
                        "request_id": request.state.request_id,
                        "gateway_request_id": gateway.get("requestId"),
                    }
                )
            )
            raise APIError(401, "UNAUTHORIZED", "유효한 관리자 세션이 필요합니다.")
        admin_trace(request, "session_authorized")
        return row

    @app.post("/api/admin/login")
    def login(payload: LoginInput, request: Request):
        # Retry optimistic conflicts so concurrent failures are all counted.
        for _ in range(10):
            admin = store.get("admins", {"username": payload.username})
            admin_trace(request, "account_read", account_found=admin is not None)
            if admin and int(admin.get("locked_until", 0)) > int(now().timestamp()):
                admin_trace(request, "account_locked")
                raise APIError(423, "ACCOUNT_LOCKED", "계정이 잠겼습니다. 15분 후 다시 시도하세요.")
            stored = admin["password_hash"] if admin else password_hash("dummy-password")
            valid = verify_password(payload.password, stored) and admin is not None
            admin_trace(request, "password_checked", valid=valid)
            if admin:
                try:
                    locked = store.login_update(admin, valid)
                except APIError as exc:
                    if exc.code == "STATE_CONFLICT":
                        admin_trace(request, "account_update_conflict")
                        continue
                    raise
                if locked:
                    admin_trace(request, "account_locked")
                    raise APIError(
                        423, "ACCOUNT_LOCKED", "계정이 잠겼습니다. 15분 후 다시 시도하세요."
                    )
            if not valid:
                raise APIError(401, "UNAUTHORIZED", "아이디 또는 비밀번호를 확인하세요.")
            token, hashed = new_token()
            deadline = now() + timedelta(seconds=settings.admin_session_ttl_sec)
            admin_trace(request, "session_write_started")
            store.put(
                "admin_sessions",
                {
                    "token_hash": hashed,
                    "username": payload.username,
                    "created_at": now().isoformat(),
                    "expires_at": deadline.isoformat(),
                    "ttl": int(deadline.timestamp()),
                },
            )
            admin_trace(request, "session_saved", expires_at=deadline.isoformat())
            return {"token": token, "expires_at": deadline.isoformat()}
        raise APIError(429, "RATE_LIMITED", "잠시 후 다시 시도하세요.")

    admin_router = APIRouter(prefix="/api/admin", dependencies=[Depends(administrator)])

    @admin_router.post("/logout")
    def logout(request: Request, session: Annotated[dict, Depends(administrator)]):
        store.delete("admin_sessions", {"token_hash": session["token_hash"]})
        admin_trace(request, "session_deleted")
        return {"ok": True}

    @admin_router.get("/stats")
    def stats(days: Annotated[int, Query(ge=1, le=7)] = 1):
        rows = []
        for offset in range(days):
            rows.extend(
                store.query_day("events", (now().date() - timedelta(days=offset)).isoformat())
            )
        return {
            "by_event": dict(Counter(row["event"] for row in rows)),
            "by_type": dict(Counter(kind for row in rows for kind in row["types"])),
            "by_source": dict(Counter(row["source"] for row in rows)),
        }

    @admin_router.get("/events")
    def events(limit: Annotated[int, Query(ge=1, le=100)] = 50, day: date | None = None):
        rows = store.query_day("events", (day or now().date()).isoformat(), limit)
        return {
            "items": [
                {key: row[key] for key in ("time", "event", "types", "source", "request_id")}
                for row in rows
            ]
        }

    @admin_router.get("/transfers")
    def transfers(
        status: Literal["ACTIVE", "PENDING_UPLOAD", "REVOKED"] | None = "ACTIVE",
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
    ):
        rows = []
        # Maximum transfer lifetime is one hour; yesterday covers midnight.
        for offset in range(2):
            rows.extend(
                store.query_day("transfers", (now().date() - timedelta(days=offset)).isoformat())
            )
        rows.sort(key=lambda row: row["created_at"], reverse=True)
        return {
            "items": [
                {
                    "id": row["transfer_id"],
                    "display_id": row["transfer_id"][:8],
                    "size": sum(int(f["size"]) for f in row["files"]),
                    "created_at": row["created_at"],
                    "encrypted": row["encrypted"],
                    **public_status(row),
                }
                for row in rows
                if (status is None or row["status"] == status)
                and datetime.fromisoformat(row["expires_at"]) > now()
            ][:limit]
        }

    @admin_router.delete("/transfers/{identifier}")
    def admin_revoke(identifier: str, request: Request):
        row = store.transfer(identifier)
        if not row:
            raise APIError(404, "NOT_FOUND", "전송을 찾을 수 없습니다.")
        return revoke(row, request, "admin")

    app.include_router(admin_router)

    key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

    def plugin_key(request: Request, key: Annotated[str | None, Depends(key_header)]):
        # REST API Gateway validates the key and applies its usage plan. Do not
        # trust a caller-supplied header when invoking the ASGI app directly.
        identity = request.scope.get("aws.event", {}).get("requestContext", {}).get("identity", {})
        if not key or not identity.get("apiKeyId"):
            raise APIError(401, "UNAUTHORIZED", "API Gateway의 유효한 API Key가 필요합니다.")

    @app.post(
        "/api/plugin/scan",
        response_model=ScanResult,
        dependencies=[Depends(plugin_key)],
        operation_id="scan_text",
    )
    def plugin_scan(payload: ScanInput, request: Request):
        result = scan(payload.text)
        event(request, "SCAN", [f["type"] for f in result["findings"]], "plugin")
        return result

    @app.post(
        "/api/plugin/transfers",
        dependencies=[Depends(plugin_key)],
        operation_id="create_transfer",
        openapi_extra={
            "requestBody": {
                "content": {"application/json": {"schema": PluginTextInput.model_json_schema()}}
            }
        },
    )
    async def plugin_transfer(
        request: Request,
        file: Annotated[UploadFile | None, File()] = None,
        expires_in: Annotated[int | None, Form()] = None,
        user_approved: Annotated[bool, Form()] = False,
    ):
        # Support the PRD's JSON text alternative as well as multipart file.
        if request.headers.get("content-type", "").split(";", 1)[0] == "application/json":
            try:
                payload = PluginTextInput.model_validate(await request.json())
            except (ValidationError, ValueError) as exc:
                raise APIError(422, "VALIDATION_ERROR", "요청 형식을 확인하세요.") from exc
            content, name, content_type = payload.text.encode(), "message.txt", "text/plain"
            expires_in, user_approved = payload.expires_in, payload.user_approved
        elif file:
            try:
                name, _ = validate_filename(file.filename, SCAN_EXTENSIONS)
                content = await read_file(file)
                content_type = "text/plain" if name.lower().endswith(".txt") else "text/csv"
            finally:
                await file.close()
        else:
            raise APIError(422, "VALIDATION_ERROR", "파일 또는 텍스트가 필요합니다.")
        if not user_approved:
            raise APIError(422, "VALIDATION_ERROR", "전송 전 사용자 승인이 필요합니다.")
        duration = expires(expires_in)
        if not content:
            raise APIError(422, "VALIDATION_ERROR", "빈 텍스트는 전송할 수 없습니다.")
        result = await run_in_threadpool(scan_file, decode_text(content))
        if result["blocked"]:
            await run_in_threadpool(
                event, request, "BLOCK", [f["type"] for f in result["findings"]], "plugin"
            )
            raise APIError(409, "SENSITIVE_DETECTED", "민감정보가 탐지되어 전송을 차단했습니다.")
        identifier = secrets.token_hex(16)
        token, hashed = new_token()
        created = now()
        deadline = created + timedelta(seconds=duration)
        item = {
            "name": name,
            "size": len(content),
            "type": content_type,
            "sha256": hashlib.sha256(content).hexdigest(),
            "s3_key": f"transfers/{identifier}/0",
        }
        row = {
            "transfer_id": identifier,
            "manage_hash": hashed,
            "status": "ACTIVE",
            "files": [item],
            "encrypted": False,
            "source": "plugin",
            "scan_ref": [],
            "created_at": created.isoformat(),
            "created_day": created.date().isoformat(),
            "expires_at": deadline.isoformat(),
            "download_count": 0,
            "ttl": int(deadline.timestamp()) + 86400,
        }
        await run_in_threadpool(storage.create, item, content)
        try:
            await run_in_threadpool(store.put, "transfers", row)
        except Exception:
            await run_in_threadpool(storage.delete, item["s3_key"])
            raise
        await run_in_threadpool(event, request, "TRANSFER", [], "plugin")
        return {**share(row, request), "manage_token": token}

    @app.get("/api/plugin/openapi.json", include_in_schema=False)
    def plugin_schema(request: Request):
        schema = get_openapi(title="SecureDrop plugin", version="1.3.0", routes=app.routes)
        schema["paths"] = {
            path: value
            for path, value in schema["paths"].items()
            if path in ("/api/plugin/scan", "/api/plugin/transfers")
        }
        schema["servers"] = [{"url": str(request.base_url).rstrip("/")}]
        return schema

    return app


app = create_app()
