# SecureDrop Cloud backend — PRD v1.3

FastAPI + Mangum 기반 Lambda 백엔드입니다. 파일은 S3, 검사·정제 메타데이터와 전송·이벤트·관리자 상태는 DynamoDB 5개 테이블에 저장합니다. SQLite와 메모리 정제 보관은 사용하지 않습니다. 탐지·정제·SecureGuard 규칙은 기존 `detector.py`, `sanitizer.py`, `intent.py`를 공유합니다.

## 실행

```powershell
cd backend
uv sync --frozen
Copy-Item .env.example .env
# .env의 FILES_BUCKET, PUBLIC_BASE_URL, ALLOWED_ORIGINS와 개발자 프로필 설정
uv run python infra/create_tables.py --profile lab
uv run python infra/create_admin.py operator --profile lab
uv run uvicorn main:app --host 127.0.0.1 --port 8000 --no-access-log
```

로컬 API 문서는 `http://localhost:8000/docs`입니다. 일반 사용자 API는 로그인과 API Key 없이 호출합니다. CORS는 명시된 웹·확장 origin만 허용하며, 비브라우저 클라이언트 인증 수단으로 사용하지 않습니다. 공개 API와 관리자 로그인 스로틀은 API Gateway에서 적용합니다. 로컬에서도 DynamoDB와 S3 또는 해당 서비스의 모의 환경이 필요합니다. 테스트는 moto를 사용하여 AWS 계정을 호출하지 않습니다.

Lambda는 Python 3.12 x86_64, `handler.handler`, 메모리 1024MB, 제한 시간 25초, 예약 동시성 10으로 구성합니다. `/prod` 경로는 Mangum이 처리합니다. 배포 패키지·권한·게이트웨이·모니터링 설정은 [배포 런북](infra/README.md)을 참고하세요.

## 웹 파일 전송 계약

1. `.txt`·`.csv`는 multipart `POST /api/scan/file`로 검사합니다(최대 4MiB). 응답은 `scan_id`, `sha256`, `filename`, `blocked`, `findings`입니다. 서버에는 원문·파일명을 저장하지 않고 해시·탐지 결과·만료만 10분 보관합니다.
2. 정제하려면 multipart `POST /api/sanitize`에 `file`, JSON 문자열 `actions`를 보냅니다. 예: `[{"action":"MASK","targets":["PHONE"]}]`. 응답의 `content_b64`를 브라우저에서 바이트로 복원하고 `preview`를 표시합니다. `sanitize_id`, 처리본 `sha256`, `findings_before`, `findings_after`, `clean`도 반환합니다. 서버는 처리본 바이트를 보관하지 않습니다. 취소 조치는 `CANCEL`이며 정제 세션을 생성하지 않습니다.
3. `POST /api/transfers`에 아래 JSON을 보냅니다. 정제본은 `scan_id` 대신 `sanitize_id`와 `user_approved:true`가 필요합니다. 잔여 민감정보를 포함한 전송은 별도로 `acknowledge_risk:true`, 검사 미지원 형식은 `acknowledge_unsupported:true`가 필요합니다. 검사·정제 참조가 만료되었거나 해시가 다르면 업로드 권한을 발급하지 않습니다.

```json
{
  "files": [{"name":"sample.txt","size":5,"type":"text/plain","sha256":"<64자리 SHA-256>"}],
  "scan_id":"<검사 응답의 ID>",
  "expires_in":600
}
```

4. 응답은 `id`, **한 번만 발급되는 `manage_token`**, `status:PENDING_UPLOAD`, `uploads[]`, `upload_expires_in:300`, `expires_at`입니다. 각 `uploads[i].fields`를 그대로 FormData에 넣고 마지막에 파일을 추가하여 `uploads[i].url`로 POST합니다. 파일 본문은 Lambda를 거치지 않습니다. 서명 정책은 객체 경로·크기 상한·암호화·SHA-256 체크섬을 고정합니다. [S3 POST 체크섬 문서](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/RESTObjectPOST.html)를 따릅니다.
5. `POST /api/transfers/{id}/complete`를 `X-Manage-Token` 헤더와 함께 호출합니다. 서버가 S3 존재·정확한 크기·실제 바이트 SHA-256을 확인한 뒤 조건부 갱신으로 `ACTIVE`로 바꿉니다. 해시 불일치는 객체를 삭제하고 `409 INTEGRITY_MISMATCH`를 반환합니다. 완료 호출 재시도는 활성 전송의 링크를 그대로 반환합니다.
6. 완료 응답의 `share_url`은 `PUBLIC_BASE_URL/d.html?id=...`이며 QR도 이 주소를 담습니다. 수신 페이지는 공개 `GET /api/d/{id}`로 `files:[{name,size,url}]`, `encrypted`, `expires_at`을 받습니다. S3 GET 링크는 최대 300초이며 전송의 남은 수명을 넘지 않습니다. 다운로드 발급 횟수를 기록합니다.
7. 상태 조회 `GET /api/transfers/{id}`와 폐기 `DELETE /api/transfers/{id}`도 같은 관리 토큰이 필요합니다. 폐기는 상태를 먼저 `REVOKED`로 바꾼 뒤 S3 객체를 삭제하여 완료 요청과의 경합을 막습니다. S3 삭제 실패 시 동일 폐기 요청을 재시도할 수 있습니다.

한 전송에 최대 5개, 합계 20MiB를 지원합니다. 다중 파일은 `files[i]`마다 `scan_id` 또는 `sanitize_id`를 넣습니다. 최상위 참조는 단일 파일일 때만 허용합니다. 만료는 300/600/3600초 중 선택하며 생성 시점부터 계산합니다. 업로드 서명과 완료 요청의 유효 시간은 5분입니다. 지원 확장자는 `.txt .csv .json .md .log .xml .yaml .yml .pdf .png .jpg .jpeg .gif .webp`입니다. 검사·정제는 TXT/CSV만 지원합니다.

`encrypted:true`는 선택 기능의 서버 계약입니다. 요청 `sha256`은 **암호문 해시**이며 S3 실제 바이트와 비교합니다. 평문 검사 세션의 해시와 암호문의 대응은 서버가 검증할 수 없습니다. AES-GCM 암호화·복호화와 키 프래그먼트는 프론트엔드가 구현해야 하며 키·IV를 API에 전달하지 않습니다.

## 기타 API

| 메서드 | 경로 | 권한 및 동작 |
|---|---|---|
| GET | `/api/health` | 공개 상태 확인 |
| POST | `/api/scan` | 공개, JSON text 최대 50,000자, 유형·개수만 반환 |
| POST | `/api/assist` | 공개, message와 context(filename/findings), 고정 조치 해석 |
| POST | `/api/ext/logs` | 공개, `event:BLOCK`, `types[]`, 출처는 서버가 extension으로 고정 |
| POST | `/api/admin/login` | username/password, 성공 시 8시간 세션 토큰 |
| POST | `/api/admin/logout` | Bearer 세션 즉시 삭제 |
| GET | `/api/admin/stats?days=1` | Bearer, 1~7일 이벤트·유형·출처 집계 |
| GET | `/api/admin/events?limit=50&day=2026-10-19` | Bearer, 지정일 최근 이벤트, 1~100개 |
| GET | `/api/admin/transfers?status=ACTIVE&limit=50` | Bearer, 전송 메타데이터, 파일명·내용·링크·토큰 제외 |
| DELETE | `/api/admin/transfers/{id}` | Bearer, 강제 폐기, source=admin 이벤트 |
| POST | `/api/plugin/scan` | API Gateway API Key, JSON text 검사 |
| POST | `/api/plugin/transfers` | API Gateway API Key, 승인 후 TXT/CSV 최대 4MiB 또는 JSON text 전송 |
| GET | `/api/plugin/openapi.json` | 위 두 플러그인 도구만 포함한 OpenAPI |

관리자 계정은 스크립트로만 생성합니다. `hashlib.scrypt(N=2**17,r=8,p=1)`와 계정별 16바이트 솔트, 상수 시간 비교를 사용합니다. 5회 실패하면 15분 잠기며 없는 아이디와 틀린 비밀번호는 같은 401 응답을 반환합니다. 관리자 세션·관리 토큰은 SHA-256 해시만 저장합니다. 계정 초기화는 `uv run python infra/reset_admin_password.py operator --profile lab`입니다. 비밀번호 초기화 시 기존 관리자 세션은 원래의 최대 8시간 만료를 유지합니다.

플러그인 JSON 예시는 `{"text":"hello","expires_in":600,"user_approved":true}`입니다. multipart는 `file`, `expires_in`, `user_approved` 필드를 사용합니다. 민감정보는 확인 플래그로 우회할 수 없고 `409 SENSITIVE_DETECTED`로 차단합니다. API Key는 Lambda 환경 변수에 저장하지 않으며 REST API Gateway가 검증한 `requestContext.identity.apiKeyId`를 확인합니다. 로컬에서 임의 `X-API-Key`만 보내면 거절합니다. 실제 AI 플랫폼 연결·승인 화면은 별도 프론트/플랫폼 작업입니다.

오류는 `{"error":{"code":"...","message":"..."}}` 형식입니다. 검증 422, 세션 인증 401, 관리 토큰 403, 미존재·폐기 404, 만료 410, 크기 초과 413, 검사 미지원 415, 잠금 423, 업로드 미완료·해시 불일치·잔여 민감정보·상태 경합 409, 저장소 오류 502로 구분합니다. 원문·비밀번호·토큰·파일명·서명 URL·대화 원문을 이벤트 및 운영 로그에 남기지 않습니다. 모든 날짜 파티션과 집계 기준은 UTC입니다.

배포된 관리자 콘솔은 `SD_CONFIG.adminApiBase: ""` 설정으로 웹과 같은 도메인의 `/api/admin/*`를 호출합니다. CloudFront는 이 경로를 API Gateway `/prod`로 전달하며, 캐시를 끄고 `Authorization`과 쿼리 매개변수를 전달합니다. 로컬에서는 기존 `apiBase`를 사용합니다. 실제 Chrome 검증은 `SD_ADMIN_USERNAME`·`SD_ADMIN_PASSWORD`를 환경 변수로 설정하거나 숨김 비밀번호 입력을 사용하여 `uv run --with playwright python infra/verify_admin_live.py`로 실행합니다.

관리자 진단 로그는 API Gateway 요청 ID로 Lambda 진입(`admin_lambda_received`), ASGI 헤더 인식(`admin_asgi_received`), 인증·세션 단계(`admin_auth_trace`)와 응답을 연결합니다. 헤더 존재 여부와 처리 결과만 기록하며 토큰·비밀번호·요청 본문은 기록하지 않습니다. API Gateway 실행 로그는 INFO, `dataTraceEnabled=false`로 설정합니다.

## v1.2에서의 전환

`backend/frontend/` 데모는 v1.3 API에 연결되어 검사·정제·승인·S3 직접 업로드·공유·폐기를 지원합니다. `extension/`은 별도 클라이언트 소스입니다. Lambda에서 정적 페이지를 제공하지 않습니다. 정적 파일은 S3 웹 버킷과 CloudFront로 배포하고, 프론트에서 API Gateway 주소를 직접 호출해야 합니다. 특히 다음 계약이 변경되었습니다.

- 전송: multipart 파일 업로드 → JSON 메타데이터 발급 → S3 직접 POST → `/complete`.
- 정제: 서버 메모리 보관 → `content_b64`를 브라우저가 보관·업로드. 기존 정제 DELETE API는 제거했습니다.
- 상태·폐기: 공개 Origin 검사 → `X-Manage-Token` 필수.
- 공유: `/d/{id}` 리다이렉트 → `d.html?id=...` 페이지와 `/api/d/{id}` JSON.
- 확장 로그: `/api/logs` → `/api/ext/logs`. 일반 로그 조회는 제거하고 관리자 경로로 이동했습니다.
- 플러그인: `/plugin/*` → `/api/plugin/*`. 키 검증·호출 한도는 API Gateway 사용량 계획으로 이동했습니다.
- 설정: `SCAN_FILE_MAX_MB=5` → `4`, `FILES_BUCKET` 사용. `DATABASE_PATH`, `SANITIZE_MEMORY_MB`, `SANITIZE_TTL_SEC`, `PLUGIN_API_KEY`는 제거했습니다.

기존 `deploy/`의 EC2 프로비저닝·배포·검증 스크립트는 v1.2용 이력입니다. v1.3 배포에는 사용하지 마세요. 기존 SQLite 데이터는 자동 이관하지 않습니다. 새 서버리스 배포 스크립트는 기존 CloudFront의 원본을 웹 S3 버킷으로 전환합니다.

## 검증

```powershell
uv run pytest -q
uv run ruff check .
uv run ruff format --check .
```

모의 S3·DynamoDB 통합 테스트로 세션 공유·만료, 크기 상한, 서명 정책, 해시 불일치 삭제, 관리 토큰, 정제 승인, 폐기 경합, 관리자 인증·잠금·로그아웃, 개인정보 제외 응답, Mangum REST 이벤트·플러그인을 검증합니다. 실제 AWS 배포, S3 브라우저 POST, CloudFront 모바일 다운로드, 성능 목표는 배포 환경에서 추가 검증해야 합니다. 발급된 S3 GET URL은 폐기 이후에도 남은 서명 시간 동안 유효할 수 있으므로 객체 삭제로 접근을 차단합니다. 업로드 POST도 만료 전 재사용될 수 있지만 서명에 고정된 동일 바이트만 허용하며 폐기 상태는 다운로드 API에서 계속 차단합니다.

## 데모 서버리스 배포

기존 `deploy/aws/resources.json`의 계정·profile과 `deployment.json`의 CloudFront·도메인을 사용합니다. 기존 EC2 배포 스크립트 대신 다음 명령을 실행합니다.

```powershell
cd backend
uv run pytest -q
uv run python infra/package_lambda.py
uv run python infra/deploy_serverless.py
# CloudFront 상태가 Deployed가 된 후
uv run python infra/configure_monitoring.py --profile default --api-id <serverless.json의 api_id>
uv run --with pillow python infra/verify_serverless.py
uv run --with playwright python -m playwright install chromium
uv run --with playwright python infra/verify_browser.py
```

배포 상태와 검증 결과는 git에서 제외된 `deploy/aws/serverless.json`, `serverless-verification.json`, `browser-verification.json`에 저장합니다. 기존 CloudFront 설정은 `cloudfront-before-serverless.json`으로 보관합니다. 스크립트는 기존 EC2를 자동 종료하지 않습니다. 검증 완료 후 해당 instance ID를 확인해 종료하고 연결된 Elastic IP를 해제하세요.

웹 화면은 저장소 루트의 `frontend/`에서 JS·CSS 하위 폴더까지 웹 S3 버킷에 업로드하고 CloudFront OAC로 제공합니다. `backend/frontend/`는 이전 테스트 콘솔이며, 이 폴더에서는 `admin.html·js·css`만 함께 배포합니다. 루트 `frontend/config.js`는 배포 시 `window.SD_CONFIG`에 API Gateway 주소와 `defaultApiMode: real`을 설정합니다. 로컬에서는 기존 mock 기본값을 유지합니다. 백엔드 폴더에서 로컬 화면은 `python -m http.server 5500 --directory ../frontend`로 열 수 있습니다. TXT·CSV는 4MiB까지, 그 외 지원 형식은 위험 확인 후 20MiB까지 단일 파일을 전송합니다. 새 웹 화면의 정제·미리보기 연결은 현재 미구현입니다. `verify_serverless.py`는 배포 파일과 로컬 소스가 같은지 확인하며 `verify_browser.py`는 실제 검사·전송·다운로드·폐기와 모바일 화면을 검증합니다.
