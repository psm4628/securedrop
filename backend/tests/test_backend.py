import base64
import hashlib
import json
from datetime import timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import boto3
import pytest
from botocore.stub import Stubber
from fastapi.testclient import TestClient
from mangum import Mangum
from moto import mock_aws

from auth import password_hash, token_hash, verify_password
from config import Settings
from detector import scan, scan_file
from errors import APIError
from infra.cors import extension_origin
from infra.create_tables import create_tables
from main import create_app
from store import Store, now


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    with mock_aws():
        settings = Settings(
            _env_file=None,
            s3_bucket="securedrop-test",
            aws_profile=None,
            public_base_url="https://demo.example.com",
        )
        s3 = boto3.client("s3", region_name=settings.aws_region)
        s3.create_bucket(
            Bucket=settings.s3_bucket,
            CreateBucketConfiguration={"LocationConstraint": settings.aws_region},
        )
        store = Store(settings)
        create_tables(store)
        app = create_app(settings, store=store)
        with TestClient(app, raise_server_exceptions=True) as client:
            yield client, app, s3


def scan_upload(client, content=b"hello", name="sample.txt"):
    response = client.post("/api/scan/file", files={"file": (name, content)})
    assert response.status_code == 200, response.text
    return response.json()


def test_extension_cors_preflight_and_auth_error(env):
    _, app, _ = env
    origin = extension_origin(Path(__file__).resolve().parents[2] / "extension" / "manifest.json")
    app.state.settings.allowed_origins = [origin]
    with TestClient(create_app(app.state.settings, app.state.storage, app.state.store)) as client:
        response = client.options(
            "/api/scan",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == origin
        response = client.get("/api/admin/stats", headers={"Origin": origin})
        assert response.status_code == 401
        assert response.headers["access-control-allow-origin"] == origin
        response = client.get("/api/admin/stats", headers={"Origin": "https://untrusted.example"})
        assert response.status_code == 401
        assert "access-control-allow-origin" not in response.headers


def issue(client, content=b"hello", name="sample.txt", **kwargs):
    result = scan_upload(client, content, name)
    payload = {
        "files": [
            {"name": name, "size": len(content), "type": "text/plain", "sha256": result["sha256"]}
        ],
        "scan_id": result["scan_id"],
        **kwargs,
    }
    response = client.post("/api/transfers", json=payload)
    return response


def put(s3, app, issued, content=b"hello", index=0):
    s3.put_object(
        Bucket=app.state.settings.s3_bucket,
        Key=issued["uploads"][index]["fields"]["key"],
        Body=content,
    )


def managed(issued):
    return {"X-Manage-Token": issued["manage_token"]}


def activate(env, content=b"hello"):
    client, app, s3 = env
    issued = issue(client, content).json()
    put(s3, app, issued, content)
    response = client.post(f"/api/transfers/{issued['id']}/complete", headers=managed(issued))
    assert response.status_code == 200, response.text
    return issued, response.json()


@pytest.mark.parametrize(
    "text,kind",
    [
        ("010-1234-5678", "PHONE"),
        ("someone@example.com", "EMAIL"),
        ("AKIA" + "A" * 16, "AWS_ACCESS_KEY"),
        ("sk-" + "a" * 24, "API_KEY"),
        ("api_key=" + "a" * 24, "API_KEY"),
        ("4111-1111-1111-1111", "CARD"),
        ("900101-1234568", "RRN"),
    ],
)
def test_detection(text, kind):
    assert {"type": kind, "count": 1} in scan(text)["findings"]
    assert text not in str(scan(text))


def test_scan_public_and_validation_privacy(env):
    client, _, _ = env
    assert client.get("/api/health").json()["status"] == "ok"
    assert client.post("/api/scan", json={"text": "hello"}).json() == {
        "blocked": False,
        "findings": [],
    }
    response = client.post("/api/scan", json={"text": "PRIVATE" * 8000})
    assert response.status_code == 422
    assert "PRIVATE" not in response.text
    assert response.headers["cache-control"] == "no-store"
    assert client.get("/api/logs").status_code == 404


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16", "cp949"])
def test_file_scan_metadata_only_and_shared_across_instances(env, encoding):
    client, app, _ = env
    text = "이름,전화\n김,010-1234-5678\n"
    content = text.encode(encoding)
    result = scan_upload(client, content, "고객정보.csv")
    assert result["findings"] == scan_file(text)["findings"]
    assert result["sha256"] == hashlib.sha256(content).hexdigest()
    other = Store(app.state.settings)
    row = other.get("sessions", {"session_id": result["scan_id"]})
    assert row["kind"] == "SCAN"
    assert row["ttl"] <= int(now().timestamp()) + 600
    assert "고객정보" not in str(row) and "010-1234-5678" not in str(row)


@pytest.mark.parametrize("path", ["/api/scan/file", "/api/sanitize"])
def test_four_mb_limit(env, path):
    client, _, _ = env
    data = {"actions": '[{"action":"MASK","targets":["PHONE"]}]'}
    assert (
        client.post(
            path, files={"file": ("a.txt", b"a" * (4 * 1024 * 1024 + 1))}, data=data
        ).status_code
        == 413
    )
    assert (
        client.post(
            path, files={"file": ("a.txt", b"a" * (4 * 1024 * 1024))}, data=data
        ).status_code
        == 200
    )


def test_presigned_post_policy_and_manage_token(env):
    client, app, _ = env
    response = issue(client)
    assert response.status_code == 200, response.text
    result = response.json()
    row = app.state.store.transfer(result["id"])
    assert row["manage_hash"] == token_hash(result["manage_token"])
    assert result["manage_token"] not in str(row)
    assert len(base64.urlsafe_b64decode(result["manage_token"] + "=")) == 32
    policy = json.loads(base64.b64decode(result["uploads"][0]["fields"]["policy"]))
    assert ["content-length-range", 1, 5] in policy["conditions"]
    assert {"key": f"transfers/{result['id']}/0"} in policy["conditions"]
    assert {
        "x-amz-checksum-sha256": base64.b64encode(hashlib.sha256(b"hello").digest()).decode()
    } in policy["conditions"]
    for headers in ({}, {"X-Manage-Token": "wrong"}):
        assert client.get(f"/api/transfers/{result['id']}", headers=headers).status_code == 403
        assert client.delete(f"/api/transfers/{result['id']}", headers=headers).status_code == 403
        assert (
            client.post(f"/api/transfers/{result['id']}/complete", headers=headers).status_code
            == 403
        )


def test_complete_download_and_revoke(env):
    client, app, s3 = env
    issued, result = activate(env)
    assert result["status"] == "ACTIVE"
    assert result["share_url"] == f"https://demo.example.com/d.html?id={issued['id']}"
    assert base64.b64decode(result["qr"].split(",")[1]).startswith(b"\x89PNG")
    download = client.get(f"/api/d/{issued['id']}")
    assert download.status_code == 200
    url = download.json()["files"][0]["url"]
    assert int(parse_qs(urlsplit(url).query)["X-Amz-Expires"][0]) <= 300
    assert app.state.store.transfer(issued["id"])["download_count"] == 1
    # Complete retries cannot create duplicate TRANSFER events.
    assert (
        client.post(f"/api/transfers/{issued['id']}/complete", headers=managed(issued)).status_code
        == 200
    )
    events = app.state.store.query_day("events", now().date().isoformat())
    assert sum(e["event"] == "TRANSFER" for e in events) == 1
    assert (
        client.delete(f"/api/transfers/{issued['id']}", headers=managed(issued)).status_code == 200
    )
    assert client.get(f"/api/d/{issued['id']}").status_code == 404
    assert (
        client.post(f"/api/transfers/{issued['id']}/complete", headers=managed(issued)).status_code
        == 404
    )
    assert not s3.list_objects_v2(Bucket=app.state.settings.s3_bucket).get("Contents")


@pytest.mark.parametrize(
    "uploaded,code",
    [(None, "UPLOAD_INCOMPLETE"), (b"no", "UPLOAD_INCOMPLETE"), (b"other", "INTEGRITY_MISMATCH")],
)
def test_completion_verifies_real_s3_bytes(env, uploaded, code):
    client, app, s3 = env
    issued = issue(client).json()
    if uploaded is not None:
        put(s3, app, issued, uploaded)
    response = client.post(f"/api/transfers/{issued['id']}/complete", headers=managed(issued))
    assert response.status_code == 409, response.text
    assert response.json()["error"]["code"] == code
    if code == "INTEGRITY_MISMATCH":
        assert app.state.store.transfer(issued["id"])["status"] == "REVOKED"
        assert not s3.list_objects_v2(Bucket=app.state.settings.s3_bucket).get("Contents")


def test_expired_session_not_accepted_even_before_ttl_cleanup(env):
    client, app, _ = env
    result = scan_upload(client)
    row = app.state.store.get("sessions", {"session_id": result["scan_id"]})
    row["ttl"] = int(now().timestamp()) - 1
    app.state.store.put("sessions", row)
    payload = {
        "files": [{"name": "a.txt", "size": 5, "sha256": result["sha256"]}],
        "scan_id": result["scan_id"],
    }
    assert client.post("/api/transfers", json=payload).status_code == 410


def test_transfer_expiry_and_delete_after_expiry(env):
    client, app, _ = env
    issued, _ = activate(env)
    row = app.state.store.transfer(issued["id"])
    row["expires_at"] = (now() - timedelta(seconds=1)).isoformat()
    app.state.store.put("transfers", row)
    assert client.get(f"/api/d/{issued['id']}").status_code == 410
    assert client.get(f"/api/transfers/{issued['id']}", headers=managed(issued)).status_code == 410
    assert (
        client.delete(f"/api/transfers/{issued['id']}", headers=managed(issued)).status_code == 200
    )


def test_sanitize_returns_bytes_and_requires_approval(env):
    client, app, s3 = env
    result = client.post(
        "/api/sanitize",
        files={"file": ("a.txt", b"010-1234-5678")},
        data={"actions": '[{"action":"MASK","targets":["PHONE"]}]'},
    ).json()
    content = base64.b64decode(result["content_b64"])
    assert content == b"010-****-5678" and result["clean"]
    row = app.state.store.get("sessions", {"session_id": result["sanitize_id"]})
    assert "content" not in row and "preview" not in row and "name" not in row
    payload = {
        "files": [{"name": "a.txt", "size": len(content), "sha256": result["sha256"]}],
        "sanitize_id": result["sanitize_id"],
    }
    assert client.post("/api/transfers", json=payload).status_code == 422
    payload["user_approved"] = True
    issued = client.post("/api/transfers", json=payload).json()
    put(s3, app, issued, content)
    assert (
        client.post(f"/api/transfers/{issued['id']}/complete", headers=managed(issued)).status_code
        == 200
    )


def test_sensitive_unsupported_and_hash_checks(env):
    client, _, _ = env
    assert issue(client, b"010-1234-5678").status_code == 409
    assert issue(client, b"010-1234-5678", acknowledge_risk=True).status_code == 200
    result = scan_upload(client)
    payload = {
        "files": [{"name": "a.txt", "size": 5, "sha256": "0" * 64}],
        "scan_id": result["scan_id"],
    }
    assert (
        client.post("/api/transfers", json=payload).json()["error"]["code"] == "INTEGRITY_MISMATCH"
    )
    payload = {"files": [{"name": "a.pdf", "size": 5, "sha256": "0" * 64}]}
    assert client.post("/api/transfers", json=payload).status_code == 422
    payload["acknowledge_unsupported"] = True
    assert client.post("/api/transfers", json=payload).status_code == 200
    payload["files"][0]["name"] = "bad.exe"
    assert client.post("/api/transfers", json=payload).status_code == 422


def test_multi_file_individual_references_and_total_limit(env):
    client, app, s3 = env
    files = []
    for content in (b"hello", b"world"):
        result = scan_upload(client, content)
        files.append(
            {"name": "a.txt", "size": 5, "sha256": result["sha256"], "scan_id": result["scan_id"]}
        )
    issued = client.post("/api/transfers", json={"files": files}).json()
    for i, content in enumerate((b"hello", b"world")):
        put(s3, app, issued, content, i)
    assert (
        client.post(f"/api/transfers/{issued['id']}/complete", headers=managed(issued)).status_code
        == 200
    )
    assert len(client.get(f"/api/d/{issued['id']}").json()["files"]) == 2
    for f in files:
        f["size"] = 11 * 1024 * 1024
    assert client.post("/api/transfers", json={"files": files}).status_code == 413


def test_revoked_record_cannot_be_activated(env):
    client, app, _ = env
    issued = issue(client).json()
    app.state.store.transition(issued["id"], "PENDING_UPLOAD", "REVOKED")
    with pytest.raises(APIError) as error:
        app.state.store.transition(issued["id"], "PENDING_UPLOAD", "ACTIVE")
    assert error.value.code == "STATE_CONFLICT"


@pytest.fixture
def admin(env):
    client, app, _ = env
    app.state.store.put(
        "admins",
        {
            "username": "operator",
            "password_hash": password_hash("test-pass"),
            "created_at": now().isoformat(),
            "failed_count": 0,
            "locked_until": 0,
        },
    )
    response = client.post(
        "/api/admin/login", json={"username": "operator", "password": "test-pass"}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer " + response.json()["token"]}


def test_scrypt_salts():
    first, second = password_hash("password"), password_hash("password")
    assert first != second
    assert first.startswith("scrypt$131072$8$1$")
    assert verify_password("password", first) and not verify_password("wrong", first)


def test_admin_auth_failure_logs_explain_reason_without_tokens(env, admin, caplog):
    client, app, _ = env
    raw_token = admin["Authorization"].split()[1]
    cases = [
        ({}, "credentials_missing_or_invalid", False),
        ({"Authorization": "Basic private-value"}, "credentials_missing_or_invalid", True),
        ({"Authorization": "Bearer private-value"}, "session_not_found", True),
    ]
    row = app.state.store.get("admin_sessions", {"token_hash": token_hash(raw_token)})
    row["expires_at"] = (now() - timedelta(seconds=1)).isoformat()
    app.state.store.put("admin_sessions", row)
    cases.append((admin, "session_expired", True))
    for headers, reason, present in cases:
        caplog.clear()
        assert client.get("/api/admin/stats", headers=headers).status_code == 401
        failures = [
            json.loads(record.message)
            for record in caplog.records
            if '"event": "admin_auth_failed"' in record.message
        ]
        assert len(failures) == 1
        assert failures[0]["reason"] == reason
        assert failures[0]["authorization_present"] is present
        assert failures[0]["request_id"]
        assert raw_token not in caplog.text
        assert token_hash(raw_token) not in caplog.text
        assert "private-value" not in caplog.text


def test_admin_failures_and_lock(env, admin):
    client, app, _ = env
    unknown = client.post("/api/admin/login", json={"username": "absent", "password": "wrong"})
    for i in range(5):
        response = client.post(
            "/api/admin/login", json={"username": "operator", "password": "wrong"}
        )
        if i < 4:
            assert response.status_code == 401 and response.json() == unknown.json()
        else:
            assert response.status_code == 423
    assert (
        client.post(
            "/api/admin/login", json={"username": "operator", "password": "test-pass"}
        ).status_code
        == 423
    )
    row = app.state.store.get("admins", {"username": "operator"})
    row["locked_until"] = int(now().timestamp()) - 1
    app.state.store.put("admins", row)
    assert (
        client.post(
            "/api/admin/login", json={"username": "operator", "password": "test-pass"}
        ).status_code
        == 200
    )


def test_admin_routes_privacy_stats_and_logout(env, admin):
    client, app, _ = env
    issued, _ = activate(env)
    assert client.get("/api/admin/transfers").status_code == 401
    assert (
        client.post("/api/ext/logs", json={"event": "BLOCK", "types": ["PHONE"]}).status_code == 200
    )
    result = client.get("/api/admin/transfers", headers=admin)
    assert result.status_code == 200
    assert (
        "sample.txt" not in result.text
        and "s3_key" not in result.text
        and "manage_hash" not in result.text
    )
    assert "share_url" not in result.text
    stats = client.get("/api/admin/stats?days=7", headers=admin).json()
    assert stats["by_event"]["TRANSFER"] == 1 and stats["by_source"]["extension"] == 1
    assert client.delete(f"/api/admin/transfers/{issued['id']}", headers=admin).status_code == 200
    assert client.get("/api/d/" + issued["id"]).status_code == 404
    events = client.get("/api/admin/events", headers=admin).json()["items"]
    assert any(e["source"] == "admin" and e["event"] == "REVOKE" for e in events)
    token = admin["Authorization"].split()[1]
    session = app.state.store.get("admin_sessions", {"token_hash": token_hash(token)})
    assert token not in str(session)
    assert client.post("/api/admin/logout", headers=admin).status_code == 200
    assert client.get("/api/admin/stats", headers=admin).status_code == 401


def test_admin_expiry_checked_without_ttl_delete(env, admin):
    client, app, _ = env
    key = token_hash(admin["Authorization"].split()[1])
    row = app.state.store.get("admin_sessions", {"token_hash": key})
    row["expires_at"] = (now() - timedelta(seconds=1)).isoformat()
    app.state.store.put("admin_sessions", row)
    assert client.get("/api/admin/stats", headers=admin).status_code == 401


def gateway_request(app, path, payload, key=True):
    event = {
        "resource": "/api/{proxy+}",
        "path": "/prod" + path,
        "httpMethod": "POST",
        "headers": {"content-type": "application/json", "x-api-key": "gateway-validated"},
        "multiValueHeaders": {},
        "queryStringParameters": None,
        "pathParameters": {"proxy": path.removeprefix("/api/")},
        "stageVariables": None,
        "requestContext": {
            "stage": "prod",
            "identity": {"sourceIp": "127.0.0.1", **({"apiKeyId": "test-key-id"} if key else {})},
        },
        "body": json.dumps(payload),
        "isBase64Encoded": False,
    }
    return Mangum(app, api_gateway_base_path="/prod", lifespan="off")(event, {})


def test_plugin_gateway_auth_and_strict_block(env):
    client, app, _ = env
    assert (
        client.post(
            "/api/plugin/scan", json={"text": "hi"}, headers={"X-API-Key": "fake"}
        ).status_code
        == 401
    )
    assert gateway_request(app, "/api/plugin/scan", {"text": "hello"})["statusCode"] == 200
    assert (
        gateway_request(app, "/api/plugin/scan", {"text": "hello"}, key=False)["statusCode"] == 401
    )
    response = gateway_request(
        app, "/api/plugin/transfers", {"text": "010-1234-5678", "user_approved": True}
    )
    assert response["statusCode"] == 409 and "SENSITIVE_DETECTED" in response["body"]
    assert gateway_request(app, "/api/plugin/transfers", {"text": "hello"})["statusCode"] == 422
    response = gateway_request(
        app, "/api/plugin/transfers", {"text": "hello", "user_approved": True}
    )
    assert response["statusCode"] == 200, response
    row = json.loads(response["body"])
    assert client.get("/api/d/" + row["id"]).status_code == 200
    schema = client.get("/api/plugin/openapi.json").json()
    assert set(schema["paths"]) == {"/api/plugin/scan", "/api/plugin/transfers"}


def test_cors_manage_and_bearer_headers(env):
    client, _, _ = env
    response = client.options(
        "/api/transfers/abc",
        headers={
            "Origin": "http://localhost:5500",
            "Access-Control-Request-Method": "DELETE",
            "Access-Control-Request-Headers": "X-Manage-Token,Authorization",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5500"


def test_storage_errors_are_redacted(env, monkeypatch):
    client, app, _ = env
    from botocore.exceptions import ClientError

    def fail(**kwargs):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "SECRET"}}, "GetItem")

    monkeypatch.setattr(app.state.store.resource.meta.client, "get_item", fail)
    response = client.get("/api/transfers/missing")
    assert response.status_code == 502 and "SECRET" not in response.text


@pytest.mark.parametrize(
    "actions",
    [
        [],
        {},
        [{"action": "EXECUTE", "targets": ["RRN"]}],
        [{"action": "MASK", "targets": ["UNKNOWN"]}],
        [{"action": "MASK"}],
        [{"action": "MASK", "targets": ["RRN", "RRN"]}],
        [{"action": "CANCEL"}, {"action": "MASK", "targets": ["RRN"]}],
        [{"action": "MASK", "targets": ["RRN"], "text": "private"}],
    ],
)
def test_invalid_sanitize_actions_do_not_persist(env, actions):
    client, app, _ = env
    response = sanitize_upload(client, b"900101-1234568", actions)
    assert response.status_code == 422 and "900101-1234568" not in response.text
    assert app.state.store.query_day("events", now().date().isoformat()) == []
    assert app.state.store.table("sessions").scan()["Count"] == 0


def test_oversize_declared_metadata_returns_413(env):
    client, _, _ = env
    response = client.post(
        "/api/transfers",
        json={"files": [{"name": "a.pdf", "size": 20 * 1024 * 1024 + 1, "sha256": "0" * 64}]},
    )
    assert response.status_code == 413


def test_delete_failure_stays_revoked_and_supports_retry(env, monkeypatch):
    client, app, s3 = env
    issued, _ = activate(env)
    original = app.state.storage.delete

    def fail(key):
        raise APIError(502, "STORAGE_ERROR", "storage unavailable")

    monkeypatch.setattr(app.state.storage, "delete", fail)
    response = client.delete(f"/api/transfers/{issued['id']}", headers=managed(issued))
    assert response.status_code == 502
    assert client.get(f"/api/d/{issued['id']}").status_code == 404
    assert (
        client.post(f"/api/transfers/{issued['id']}/complete", headers=managed(issued)).status_code
        == 404
    )
    monkeypatch.setattr(app.state.storage, "delete", original)
    assert (
        client.delete(f"/api/transfers/{issued['id']}", headers=managed(issued)).status_code == 200
    )
    assert not s3.list_objects_v2(Bucket=app.state.settings.s3_bucket).get("Contents")


def test_plaintext_hash_bypass_only_allowed_for_encrypted_transfers(env):
    client, app, s3 = env
    scanned = scan_upload(client)
    content = b"encrypted-demo-ciphertext"
    payload = {
        "files": [
            {"name": "a.txt", "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        ],
        "scan_id": scanned["scan_id"],
        "encrypted": True,
    }
    issued = client.post("/api/transfers", json=payload).json()
    put(s3, app, issued, content)
    assert (
        client.post(f"/api/transfers/{issued['id']}/complete", headers=managed(issued)).status_code
        == 200
    )
    assert client.get(f"/api/d/{issued['id']}").json()["encrypted"] is True


def test_scan_reference_does_not_bypass_sensitive_checks_with_different_extension(env):
    client, _, _ = env
    scanned = scan_upload(client, b"010-1234-5678")
    response = client.post(
        "/api/transfers",
        json={
            "files": [{"name": "a.pdf", "size": 13, "sha256": scanned["sha256"]}],
            "scan_id": scanned["scan_id"],
            "acknowledge_unsupported": True,
        },
    )
    assert response.status_code == 409


def test_multipart_never_rolls_to_disk_and_logs_exclude_secrets(env, monkeypatch, caplog):
    import tempfile

    client, _, _ = env

    def fail(self):
        raise AssertionError("File contents must stay in RAM")

    monkeypatch.setattr(tempfile.SpooledTemporaryFile, "rollover", fail)
    response = client.post(
        "/api/sanitize",
        files={"file": ("private-file.csv", b"name,phone\n" + b"Kim,010-1234-5678\n" * 65000)},
        data={"actions": '[{"action":"MASK","targets":["PHONE"]}]'},
    )
    assert response.status_code == 200 and response.json()["clean"]
    logs = "\n".join(r.message for r in caplog.records if r.name == "securedrop")
    assert "010-1234-5678" not in logs and "private-file.csv" not in logs


def sanitize_upload(client, content, actions):
    return client.post(
        "/api/sanitize",
        files={"file": ("sample.csv", content)},
        data={"actions": json.dumps(actions)},
    )


def test_detection_negative_and_counts():
    assert not scan("일반 문장 900101-1234567 4111-1111-1111-1112")["blocked"]
    assert scan("010-1234-5678 010-2222-3333")["findings"] == [{"type": "PHONE", "count": 2}]
    text = " " * 48_995 + "010-1234-5678" + " " * 51_000 + "010-9999-8888"
    assert scan_file(text)["findings"] == [{"type": "PHONE", "count": 2}]


@pytest.mark.parametrize(
    "message,action,targets",
    [
        ("주민등록번호만 가리고 보내줘", "MASK", ["RRN"]),
        ("전화번호 삭제해줘", "DELETE", ["PHONE"]),
        ("전체 마스킹", "MASK", ["RRN", "PHONE"]),
        ("전송 취소", "CANCEL", []),
        ("파일을 보내줘", "CLARIFY", []),
        ("주민번호 마스킹하지 마", "CLARIFY", []),
        ("주민번호 마스킹하고 전화번호 삭제", "CLARIFY", []),
        ("이메일 삭제", "CLARIFY", []),
    ],
)
def test_assistant_metadata_and_fixed_actions(env, message, action, targets):
    client, _, _ = env
    context = {
        "filename": "private-name.csv",
        "findings": [{"type": "RRN", "count": 2}, {"type": "PHONE", "count": 1}],
    }
    response = client.post("/api/assist", json={"message": message, "context": context})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["action"] == action and result["targets"] == targets
    assert {option["action"] for option in result["options"]} == {"MASK", "DELETE", "CANCEL"}
    assert "private-name.csv" not in response.text
    context["text"] = "900101-1234568"
    rejected = client.post("/api/assist", json={"message": message, "context": context})
    assert rejected.status_code == 422 and "900101-1234568" not in rejected.text


def test_scanning_and_sanitization_use_same_boundary_rules(env):
    client, _, _ = env
    # A token may exceed the old 1,000-character overlap used by file scanning.
    text = " " * 48_995 + "sk-" + "a" * 2000 + " someone@example.com"
    assert scan_file(text) == scan(text)
    response = sanitize_upload(
        client, text.encode(), [{"action": "MASK", "targets": ["API_KEY", "EMAIL"]}]
    )
    result = response.json()
    assert result["findings_before"] == scan(text)["findings"]
    assert result["clean"] and not result["findings_after"]


def test_missing_s3_upload_without_list_bucket_permission_stays_pending(env):
    client, app, _ = env
    pending = issue(client).json()
    storage = app.state.storage
    with Stubber(storage.client) as stub:
        stub.add_client_error(
            "head_object",
            service_error_code="403",
            http_status_code=403,
            expected_params={
                "Bucket": app.state.settings.s3_bucket,
                "Key": pending["uploads"][0]["fields"]["key"],
            },
        )
        response = client.post(f"/api/transfers/{pending['id']}/complete", headers=managed(pending))
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "UPLOAD_INCOMPLETE"
    assert app.state.store.transfer(pending["id"])["status"] == "PENDING_UPLOAD"


def test_extension_log_contract_is_strict_and_type_only(env):
    # extension/background.js sends exactly {"event","types"}; source is fixed by the server.
    client, app, _ = env
    ok = client.post("/api/ext/logs", json={"event": "BLOCK", "types": ["RRN", "PHONE"]})
    assert ok.status_code == 200 and ok.json() == {"ok": True}
    for body in (
        {"event": "BLOCK", "types": ["RRN"], "source": "extension"},
        {"event": "BLOCK", "types": ["RRN"], "text": "900101-1234568"},
        {"event": "BLOCK", "types": []},
        {"event": "BLOCK", "types": ["SSN"]},
        {"event": "SCAN", "types": ["RRN"]},
    ):
        assert client.post("/api/ext/logs", json=body).status_code == 422
    rows = app.state.store.query_day("events", now().date().isoformat())
    assert [(r["event"], r["source"], r["types"]) for r in rows] == [
        ("BLOCK", "extension", ["PHONE", "RRN"])
    ]


def test_every_admin_route_requires_session_by_default(env, admin):
    client, app, _ = env
    paths = {
        path
        for path in app.openapi()["paths"]
        if path.startswith("/api/admin/") and path != "/api/admin/login"
    }
    assert paths  # guard against the prefix check silently matching nothing
    for path in paths:
        concrete = path.replace("{identifier}", "x")
        for method in ("GET", "POST", "DELETE"):
            response = client.request(method, concrete)
            assert response.status_code in (401, 405), (method, path, response.status_code)
            wrong = client.request(method, concrete, headers={"Authorization": "Bearer nope"})
            assert wrong.status_code in (401, 405), (method, path, wrong.status_code)
