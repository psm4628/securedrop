# SecureDrop Cloud Frontend (C)

PRD v1.3 웹 UI입니다. Vanilla JS(ES modules), 빌드 없음, 외부 스크립트 없음(CloudFront CSP `script-src 'self'` 대응).
`backend/frontend/`는 A의 v1.2 백엔드 테스트 화면이며 v1.3 API와 맞지 않습니다. 데모 화면은 이 폴더입니다.


## 실행

```bash
cd frontend && python3 -m http.server 5500
```

- `http://localhost:5500/?api=mock` — 서버·S3 없이 mock으로 동작 (기본값)
- `http://localhost:5500/?api=real` — `config.js`의 `apiBase`에 연결
- 선택한 모드는 브라우저에 기억됩니다. 화면 오른쪽 위 배지로 현재 모드를 확인하세요.
- mock 모드에서도 QR 링크(`d.html?id=…`)를 같은 브라우저 새 탭에서 열면 다운로드 화면을 확인할 수 있습니다. 1MB 이하 파일만 실제로 저장됩니다.

배포 주소(API Gateway `/prod`)는 웹 루트의 `config.js`(`window.SD_CONFIG.apiBase`) 한 곳만 바꾸면 됩니다. B의 관리자 콘솔(`admin.html`)도 같은 파일을 읽으므로, 배포 시 `admin.*`를 이 폴더에 함께 두면 됩니다.
테스트 파일은 저장소 루트 `samples/`에 있습니다. 모두 가상 데이터입니다.

## 페이지와 파일

| 파일 | 역할 |
|---|---|
| `index.html` | 업로드 + SecureGuard 패널 + QR 결과 |
| `d.html` | 휴대폰 다운로드 페이지 (`GET /api/d/{id}`) |
| `config.js` | 배포 주소 `window.SD_CONFIG` (`apiBase`, `cloudwatchUrl`) — 관리자 콘솔과 공유 |
| `js/settings.js` | 상한(전송 20MB·검사 4MB), 확장자, 만료 선택지, mock 전환 |
| `js/api.js` | API 클라이언트 + v1.3 계약을 흉내 내는 mock, SHA-256 |
| `js/upload.js` | 선택 → `/api/scan/file` → 해시 → `/api/transfers` → S3 직접 업로드 → `/complete` |
| `js/manage.js` | 관리 토큰 보관 (sessionStorage), `X-Manage-Token` |
| `js/qr.js` | QR, 만료 카운트다운, 다운로드 수, 링크 복사·폐기 |
| `js/download.js` | 다운로드 페이지 로직 |
| `js/assist.js` | SecureGuard 패널 (규칙 기반 문구 + 조치 버튼) |
| `js/crypto.js` | (B) 브라우저 암호화 F12 — AES-256-GCM 암호화·복호화, 키는 링크 `#k=`에만 |
| `js/qrcode.js` | (B) 브라우저 QR 생성기 — 키가 든 링크는 서버가 QR을 못 만들어 브라우저에서 그린다 |
| `js/main.js`, `js/ui.js` | 진입점, 토스트·공통 도우미 |

## 백엔드 계약 메모

`backend/README.md`(A, v1.3)의 "웹 파일 전송 계약"을 따릅니다. 화면 동작에 영향이 큰 규칙:

- .txt/.csv는 검사(`scan_id`) 또는 정제(`sanitize_id`) 참조가 있어야만 전송됩니다. 그래서 4MB를 넘는 .txt/.csv는 보낼 수 없다고 안내합니다.
- 그 외 형식은 `acknowledge_unsupported`, 민감정보가 남은 파일은 `acknowledge_risk`(없으면 409 `SENSITIVE_REMAINS`), 처리본은 `user_approved`가 필요합니다.
- 로컬 실행 시 백엔드 `.env`의 `ALLOWED_ORIGINS`에 `http://localhost:5500`, `PUBLIC_BASE_URL`은 `http://localhost:5500`으로 두면 QR이 이 폴더의 `d.html`을 가리킵니다. S3 버킷 CORS에도 `http://localhost:5500`이 있어야 합니다.

## 진행 상황

- [x] STEP 1~2: 선택 즉시 검사, 민감정보 원본 보류, 검사 미지원 형식 확인, 4MB 초과 .txt/.csv 차단
- [x] 3단계 업로드(SHA-256, Presigned POST, 진행률), 관리 토큰, QR, 상태 조회, 폐기
- [x] `d.html` 휴대폰 다운로드 (만료 410·폐기 404 화면)
- [ ] 여정 3~4: SecureGuard 조치 → `/api/sanitize` → 미리보기 승인 → 처리본 전송 (Day 3)
- [ ] 자연어 요청 `/api/assist`, 플러그인 도구 (Day 4)
- [ ] 선택: 내 전송 목록(F11), 다중 파일(F10), 브라우저 E2EE(F12)

## 브라우저 암호화 (F12, 선택)

- 업로드 화면의 "브라우저에서 암호화해서 보내기"를 켜면 검사·정제·승인은 평문으로 끝낸 뒤 **업로드 직전에** AES-256-GCM으로 암호화한다. 서버에는 `encrypted: true`와 **암호문**의 크기·SHA-256을 보내고, 키는 어디에도 보내지 않는다.
- 암호문 형식은 `[IV 12바이트][암호문+태그 16바이트]`로 평문보다 28바이트 크다. 20MB에 딱 맞는 파일은 암호화하면 상한을 넘을 수 있어 안내 문구를 띄운다.
- 공유 링크는 `d.html?id=…#k=<키 43자>`. `#` 뒤는 HTTP 요청에 실리지 않는다. 키가 든 링크는 서버가 QR을 만들 수 없어 `js/qrcode.js`로 브라우저에서 다시 그린다(버전 1~10, 213바이트까지).
- `d.html`은 S3에서 암호문을 받아 브라우저에서 복호화해 저장한다. 키가 틀렸거나 내용이 바뀌면 GCM 태그 검증이 실패해 아무것도 저장하지 않는다.
- 한계: 검사 단계에서는 서버가 평문을 본다. QR을 가진 사람은 키도 가진다. 링크를 복사하면 키까지 복사된다.
- 테스트: `cd frontend && node --test tests/crypto.test.mjs`
