# SecureDrop Cloud 제품 요구사항 문서 (PRD) v1.3

> 원본 PDF(`SecureDrop_Cloud_PRD_v1.3_5.pdf`, 2026-10-19)를 마크다운으로 변환한 문서다. 그림(8.2, 8.3)은 포함하지 않았고, 표·코드는 읽기 쉽게 다시 정리했다. 이후 팀이 추가한 WAF·KMS·CloudTrail은 이 문서에 반영되어 있지 않다.


Oct 19, 2026

AI 시대의 안전한 데이터 출입구: 민감정보 탐지·정제 + QR 파일 전송 + AI 입력 차단. v1.3은 인프라를 AWS 핵심 서비스 6개 기반 서버리스 구조로 확정하고, 로그인 없는 사용자 흐름과 관리자 전용 로그인·S3 직접 업로드·전송 이력 저장·모니터링을 구체화한 버전이다.

| 항목 | 내용 |
|---|---|
| 제품명 | SecureDrop Cloud (가칭) |
| 문서 버전 | v1.3 (AWS 서버리스 아키텍처 반영) |
| 작성일 | 2026-10-19 |
| 프로젝트 성격 | 5일 · 3인 팀 데모 프로젝트 |
| AWS 리전 | ap-northeast-2 (서울). CloudFront만 글로벌 |
| 사용 AWS 서비스 | S3, Lambda, API Gateway, DynamoDB, CloudFront, CloudWatch (6개). Cognito는 쓰지 않음 |

v1.2 대비 변경 사항

NEW 는 새로 추가된 항목, 변경은 v1.2 값이 바뀐 항목, 선택은 일정에 여유가 있을 때만 구현하는 항목이다. v1.3의 핵심은 "EC2 서버 1대" 가정을 CloudFront → API

Gateway → Lambda → S3·DynamoDB·CloudWatch 구조로 바꾸고, 그에 따라 달라지는 한도·인증·저장 방식을 명세에 반영한 것이다.

| 위치 | 변경 내용 |
|---|---|
| 8. 아키텍처 · 10. AWS 인프라 | 변경 EC2 + Nginx → Lambda(FastAPI + Mangum) + API Gateway(REST) + CloudFront. 서비스별 설정값, IAM 정책, 서비스 한도, 배포 절차를 10장에 새로 기술 |
| F9 사용자 로그인 → F13 관리자 로그인 | 변경 일반 사용자 로그인은 두지 않는다(F9 삭제). 사용자는 로그인 없이 쓰고, 자기 전송의 조회·폐기는 전송을 만들 때 받는 관리 토큰으로 한다. 로그인은 관리자만 하며 F13(운영 모니터링·관리자 콘솔)에 넣었다. 관리자 계정은 DynamoDB sd_admins 에 아이디와 scrypt 비밀번호 해시 만 저장. Cognito는 쓰지 않음 |
| F1 QR 파일 전송 | 변경 파일이 Lambda를 거치지 않고 브라우저 → S3 직접 업로드(Presigned POST). QR에는 S3 URL이 아니라 다운로드 페이지 링크를 담고, 다운로드 시점에 권한 확인 후 5분짜리 Presigned GET을 발급 |
| F2 · F7 파일 검사·정제 상한 | 변경 /api/scan/file · /api/sanitize 파일 상한 5MB → 4MB. Lambda 동기 호출 페이로드 6MB 한도와 multipart base64 인코딩(약 1.33배) 때문 |
| F7 처리본 보관 | 변경 "서버 메모리 TTL 보관"은 Lambda에서 성립하지 않으므로, 처리본은 응답으로 브라우저에 돌려주고 서버에는 해시·결과 메타데이터만 DynamoDB(TTL 10분)에 남김 |
| F6 로그 저장소 | 변경 DynamoDB로 확정(SQLite 선택지 삭제). 전송 세션·전송 이력·이벤트 로그 3개 테이블 + 관리자 계정·관리자 세션 2개 테이블 |
| F10 · F11 · F12 | NEW 선택 다중 파일 전송, 내 전송 목록(브라우저 보관), 브라우저 E2EE(AES-256-GCM) 시연 |
| F13 운영 모니터링·관리자 콘솔 | NEW CloudWatch 로그 보존 14일, 운영 대시보드, 오류 알람. 관리자 전용 로그인과 관리자 콘솔(이벤트 집계, 최근 이벤트, 활성 전송, 강제 폐기) |
| 9. API 명세 | 변경 인증 방식 열 추가. 업로드가 2단계( POST /api/transfers → S3 → /complete )로 바뀜. 공개 다운로드 GET /api/d/{id} , 관리자 /api/admin/* , 확장 로그 /api/ext/logs , 플러그인 전용 /api/plugin/* 추가 |
| 오류 코드 | NEW FORBIDDEN , ACCOUNT_LOCKED , UPLOAD_INCOMPLETE , INTEGRITY_MISMATCH , SENSITIVE_DETECTED |
| 11. 마일스톤 | 변경 Day 1 인프라 생성, Day 2 Lambda 배포, Day 4 HTTPS 통합 테스트 중심으로 재배치. 3인 역할에 관리자 콘솔·암호화 시연 반영 |
| 2. 비목표 | NEW 이번에 제외한 AWS 서비스 10개(Cognito 포함)와 제외 이유, 대체 방법 명시 |

이 방식을 택한 이유

EC2 1대 구성은 서버 패치·HTTPS 인증서·프로세스 관리가 팀 시간을 잡아먹는다. Lambda + API Gateway + CloudFront는 HTTPS가 기본 제공되고 서버 관리가 없다.

Lambda를 쓰면 요청·응답 6MB 한도가 생긴다. 그래서 큰 파일(20MB)은 Lambda를 거치지 않고 S3로 직접 올리고, Lambda는 "발급·검증·기록"만 맡는다. 이 구조는 전송 성능 과 비용에도 유리하다.

Lambda는 상태를 기억하지 않으므로 서버 메모리에 두던 정제 세션을 DynamoDB로 옮겼다. 원문은 여전히 저장하지 않고, 해시·유형·개수만 남긴다.

탐지 규칙은 계속 detector.py 하나다. "탐지 규칙 통일" 원칙은 그대로 유지된다.

## 1. 개요

SecureDrop Cloud는 파일이나 텍스트가 나가기 전에 위험한 정보를 찾아내고, 사용자가 원하는 범위만 정제(마스킹·삭제)한 뒤 다시 검증하여, QR 코드로 PC와 휴대폰 사이에서 안전하게 전달하는 웹 서비스다.

QR 파일 전송: 앱 설치 없이 PC → 휴대폰으로 파일을 전달한다. 파일은 브라우저에서 S3로 직접 올라가고, 링크는 짧은 시간만 유효하다.

민감정보 탐지·정제: 주민등록번호·전화번호·API Key 등을 찾아 이유를 설명하고, 사용자가 선택한 조치(마스킹/삭제/취소)를 검증된 코드로 처리한 뒤 재검사한다.

크롬 확장프로그램: AI 서비스 입력창에 들어가는 민감정보를 전송 직전에 차단하고 "안전한 전송 경로"로 안내한다.

AI 플러그인: Claude·ChatGPT가 이 서비스를 승인된 통로로만 쓰도록 scan_text , create_transfer 두 도구를 제공한다.

관리자 콘솔 NEW : 사용자는 로그인 없이 쓰고, 관리자만 로그인해 차단·전송 현황을 보고 의심스러운 전송을 강제 폐기한다.

QR은 전송 수단이고, 제품의 차별점은 "위험 탐지 → 이유 설명 → 사용자 선택 → 정보 정제 → 재검증 → 안전한 전송"이 하나의 여정으로 이어진다는 점이다.

| 항목 | 내용 |
|---|---|
| 리전 | ap-northeast-2 (서울) |
| 인증 변경 | 일반 사용자: 로그인 없음. 자기 전송의 조회·폐기는 전송별 관리 토큰. 관리자: 아이디·비밀번호 로그인 후 관리자 세션 토큰. 플러그인: API Gateway API Key + 사용량 계획. AWS 접근: Lambda 실행 역할(IAM Role). 개발자는 AWS CLI profile. 코드·확장프로그램·프론트엔드에 AWS 키 포함 금지 |
| 범위 | 5일·3인 팀 데모. 끝까지 동작하는 하나의 시나리오가 목표. 다중 조직·관리자 콘솔은 범위 밖 |
| 데모 지원 파일 | 탐지·정제는 텍스트(.txt)·CSV 한 계열을 먼저 완성하고, Excel·PDF는 향후 확장 |

## 2. 목표 및 비목표

목표는 "AI 입력 차단 → 민감정보 정제 → 안전한 QR 전송 → AI 플러그인 연동"까지 이어지는 데모 하나를 AWS 서버리스 위에서 5일 안에 완성하는 것이다.

목표

QR 파일 전송: 검사 → S3 직접 업로드 → 전송 기록(DynamoDB) → QR → 휴대폰 다운로드

민감정보 탐지: /api/scan (텍스트)과 /api/scan/file (파일). 둘 다 원문 비저장

민감정보 정제: 마스킹/삭제 처리본 생성, 처리본 재검사, 미리보기 후 승인해야 전송

SecureGuard 해결 도우미: 탐지 결과 설명, 선택 가능한 조치 제시, 사용자 요청을 정해진 조치로 해석

크롬 확장: AI 사이트 입력창 전송 직전 검사, 차단 시 팝업과 서버 로그 전송

AI 플러그인: scan_text , create_transfer 2개 도구를 OpenAPI 또는 MCP 중 하나로 제공

NEW 관리자 전용 로그인과 관리자 콘솔(이벤트 집계, 활성 전송 확인, 강제 폐기). 일반 사용자는 로그인 없이 사용

NEW AWS 6개 서비스를 최소 권한·퍼블릭 차단·로그 보존 기준으로 구성하고 CloudWatch 대시보드로 시연

선택 다중 파일 전송, 내 전송 목록(브라우저 보관), 브라우저 E2EE 시연

비목표 (발표 시 "향후 계획")

일반 사용자 회원가입·로그인, 계정 기반 개인 클라우드, 다중 조직, 관리자 MFA·비밀번호 재설정(분실 시 스크립트로 초기화)

AWS 리소스 관리 챗봇(EC2 시작·종료 등). 보안 설정 점검 기능과의 연결은 향후 검토

Excel·PDF·이미지 내부의 민감정보 검사·정제 (이번 버전은 텍스트/CSV)

1회 다운로드 강제, 바이러스 검사, KMS 고객 관리형 키 암호화

ChatGPT·Claude 외 다수 사이트 동시 지원 (확장은 한 사이트만 확실히)

다중 리전·고가용성, IaC(코드형 인프라) 자동화

이번에 제외한 AWS 서비스 NEW

| 서비스 | 쓰려던 용도 | 이번 버전의 대체 방법 |
|---|---|---|
| Cognito | 회원가입·로그인, 토큰 발급 | 일반 사용자 로그인 없음. 관리자 로그인만 Lambda 자체 인증( sd_admins 에 아이디 + scrypt 해 시, F13) |
| EventBridge | 파일 만료 이벤트 | S3 수명 주기 규칙(1일) + 조회 시점에 expires_at 비교 |
| SQS | 비동기 처리 | 파일 상한(검사 4MB)으로 동기 처리 시간 안에 끝냄 |
| KMS | 키 관리 (E2EE 확장 시) | S3 기본 암호화(SSE-S3), E2EE 키는 브라우저에서 생성해 URL 프래그먼트로만 전달 |
| WAF | 보안 강화 | API Gateway 스로틀링·사용량 계획, CORS 제한, 입력 검증 |
| SES | 이메일 알림 | 이메일 발송 없음 |
| Step Functions | 복잡한 워크플로 | 업로드 2단계(발급 → 완료 확인)를 API 2개로 단순화 |
| CloudTrail | 감사 로그 | 계정 기본 이벤트 기록(90일 조회)만 사용, 별도 트레일 미생성 |
| AWS CDK | 인프라 코드화 | AWS CLI 스크립트 + 설정 런북( infra/ )으로 재현성 확보 |
| AWS Budgets | 비용 관리 | 사용량 상한(예약 동시성·스로틀)으로 비용 폭주 방지, Day 5 리소스 정리 체크리스트 |

## 3. 대상 사용자 및 사용 시나리오

주 사용자는 업무 중 AI 서비스를 쓰면서 파일을 기기 간에 옮겨야 하는 직장인·학생이며, 보조 사용자는 Claude·ChatGPT 같은 AI 에이전트다.

| 시나리오 | 사용자 행동 | 기대 결과 |
|---|---|---|
| 관리자 점검 NEW | 관리자가 admin.html 에 로그인 | 오늘 차단·정제·전송 건수와 최근 이벤트 확인, 의심스러운 전송 강제 폐기. 파일 내용· 파일명은 보이지 않음 |

| AI 입력 차단 | ChatGPT 입력창에 주민등록번호를 넣고 전송 | 전송이 막히고 "민감정보 감지" 팝업, 차단 로그(유형·시간) 저장 |
|---|---|---|
| 안전 경로 안내 | 팝업의 "안전하게 전송하기" 클릭 | SecureDrop 업로드 페이지(CloudFront)로 이동 |
| QR 파일 전송 | PC에서 파일 선택 | 검사 → S3 직접 업로드 → 만료형 링크와 QR 표시, 휴대폰 스캔 시 설치 없이 다운로 드 |
| 민감정보 정제 | 고객정보.csv를 선택하고 챗봇에 "주민등록번호만 가리고 보내줘" | 선택 즉시 검사 → 원본 전송 보류 → 마스킹 처리본 생성 → 재검사 통과 → 미리보 기 승인 → QR 전송 |
| 만료·폐기 | 만료 시간 경과 또는 "링크 폐기" 클릭 | 다운로드 페이지가 "만료/폐기된 링크" 표시, S3 객체 삭제 |
| AI 연동 | AI에게 "이 파일 폰으로 보내줘" 요청 | AI가 scan_text 검사 후 사용자 승인을 받고 create_transfer 로 링크·QR 반 환, 위험하면 차단 사유 설명 |
| 암호화 전송 선택 | "브라우저 암호화" 옵션을 켜고 전송 | S3에는 암호문만 저장, 휴대폰 브라우저에서 복호화되어 원본 파일 저장 |

## 4. 핵심 사용자 여정 (8단계) 변경

v1.2의 5단계 여정을 인프라 흐름에 맞춰 8단계로 나눴다. 단계 1~4는 v1.2와 같은 의미이고, 5~8은 업로드·공유·다운로드가 어떤 AWS 경로를 타는지를 드러낸다.

| # | 단계 | 사용자에게 보이는 것 | 뒤에서 일어나는 일 |
|---|---|---|---|
| 1 | 파일 선택 | 보낼 파일을 고른다(로그인 없음) | 확장자·크기 1차 검사(브라우저) |
| 2 | 민감정보 검사 | "고객정보.csv에 주민등록번호 2건 발견", 원본 전송 보류 | POST /api/scan/file → Lambda가 메모리에서 검사, 결과· 해시만 DynamoDB sd_sessions 에 저장 |
| 3 | 마스킹·삭제 | SecureGuard가 이유를 설명, 사용자가 조치 선택 | /api/assist 가 요청을 고정 조치값으로 해석, /api/sanitize 가 처리본 생성 후 재검사 |
| 4 | 미리보기 승인 | 처리본 상위 20행 확인 후 "승인" | 처리본은 브라우저 메모리에만 있음. 서버에는 처리본 해시만 기록 |
| 5 | 브라우저 암호화 선택 | "암호화해서 보내기" 체크 | Web Crypto API로 AES-256-GCM 암호화. 키는 서버로 보내지 않 음 |
| 6 | S3 업로드 | 진행률 표시 | POST /api/transfers 로 Presigned POST 발급 → 브라우저 가 S3에 직접 업로드 → /complete 로 확인 |
| 7 | QR 전송·공유 | QR 코드, 링크, 남은 시간, "링크 폐기" 버튼 | DynamoDB 전송 상태 ACTIVE , 공유 링크 = CloudFront 다운로 드 페이지 + 전송 ID (+ #k= 키) |
| 8 | 다운로드·복호화 | 휴대폰에서 파일 저장 | GET /api/d/{id} 가 상태·만료 확인 후 5분짜리 Presigned GET 발급 → S3 직접 다운로드 → (암호화 시) 브라우저 복호화 |

챗봇 대화 예시

SecureGuard: 선택한 고객정보.csv에서 민감정보가 발견됐습니다. 주민등록번호 형식 2건. 원본 파일의 전송이 보류되었습니다.

사용자: 주민등록번호만 가리고 보내줘.

SecureGuard: 주민등록번호를 900101-1****** 형식으로 마스킹하겠습니다. 원본은 변경하지 않고 별도 처리본을 만들며, 처리 후 다른 민감정보가 남았는지 다시 검사합니다. 선택 버튼: [ 주민등록번호 마스킹 ] [ 해당 항목 삭제 ] [ 전송 취소 ]

## 5. 설계 원칙 및 보안 위험

세 원칙: 탐지 엔진이 판정하고, 검증된 코드가 처리하며, 사용자가 확인해야 전송한다. v1.3은 여기에 인프라 원칙 하나를 더한다.

1. 원칙 1. 탐지 엔진이 위험을 판정하고, 챗봇은 그 결과를 설명하고 사용자 요청을 해석만 한다.

2. 원칙 2. 실제 마스킹·삭제는 검증된 처리 코드가 수행한다. AI에게 파일 내용을 임의로 고치도록 맡기지 않는다.

3. 원칙 3. 처리본을 다시 검사한 뒤, 사용자가 결과를 확인하고 승인해야 전송한다.

4. 원칙 4 NEW . 파일 바이트는 S3에만, 판단 기록은 DynamoDB에만, 운영 신호는 CloudWatch에만 둔다. 어느 곳에도 민감정보 원문을 로그로 남기지 않는다.

| 위험 | 필요한 대응 |
|---|---|
| 민감정보가 서버로 그대로 전송됨 | 검사·정제 단계에서는 Lambda 메모리에서만 다루고 저장·로깅하지 않는다(HTTPS 필수). E2EE를 켜도 검사 단계에서는 서 버가 평문을 본다는 점을 문서·발표에 명시하고, 브라우저 로컬 검사는 향후 과제로 둔다. |
| QR 링크가 다른 사람에게 노출됨 | 짧은 만료(기본 10분, 상한 60분), 즉시 폐기, 전송 ID는 추측 불가한 128비트 난수, S3 URL 자체는 다운로드 시점에 5분짜리 로만 발급. 링크 전체는 로그에 남기지 않음 |
| 마스킹 후 다른 민감정보가 남음 | 처리본을 재검사하고, 통과해야 전송 허용 |
| 원본·임시 파일이 남음 | S3 수명 주기 규칙으로 1일 후 자동 삭제, 정제 처리본은 서버에 저장하지 않음, 버킷 버전 관리 끔 |
| AI가 잘못 판단함 | 차단·허용은 규칙 기반 검사 결과로만 결정. 챗봇은 정해진 조치 값(MASK/DELETE/CANCEL/CLARIFY)으로만 해석 |
| 챗봇에 민감정보 원문이 노출됨 | 챗봇(및 LLM 사용 시)에는 유형·개수·파일명 등 메타정보만 전달 |
| 프롬프트 인젝션(문서 속 악성 지시) | create_transfer 호출 전 사용자 승인, 파일 조회·다운로드 도구 미제공 |

| 검사 미지원 형식이 검사 없이 전송됨 | .txt·.csv 외 형식은 "민감정보 검사를 지원하지 않습니다" 표시 후 사용자 확인 필요. 서버도 acknowledge_unsupported 없으면 거부 |
|---|---|
| 검사한 파일과 올라간 파일이 다름 NEW | 검사·정제 결과의 SHA-256을 DynamoDB에 저장하고, /complete 에서 S3 객체 해시와 비교(불일치 시 삭제·409). 암호화 전송은 서버가 평문 해시를 확인할 수 없으므로 데모 한계로 명시 |
| 관리 토큰·관리자 세션 탈취(XSS) NEW | 서버에는 두 토큰 모두 SHA-256 해시만 저장. 관리자 세션은 sessionStorage에만 두고 유효 8시간, 로그아웃 시 삭제. CloudFront 응답 헤더 정책으로 CSP·HSTS 적용, 외부 스크립트 금지 |
| 관리자 비밀번호 유출·무차별 대입 NEW | 비밀번호 원문은 저장·로깅하지 않고 scrypt(솔트 포함) 해시만 저장. 5회 실패 시 15분 잠금, 관리자 로그인 API는 초당 1회 스로틀, 가입 API 없음(계정은 스크립트로만 생성). 선택: API Gateway 리소스 정책으로 /api/admin/* 를 팀 IP로 제한 |
| 로그인 없는 API 남용 NEW | 사용자 API가 모두 공개이므로 스테이지·메서드 스로틀, 파일 크기 상한, Lambda 예약 동시성 10으로 상한을 둔다. 관리자 콘 솔에서 비정상 증가를 확인하고 필요 시 강제 폐기 |
| S3 버킷 공개 노출 NEW | 퍼블릭 액세스 전체 차단, 웹 버킷은 CloudFront OAC로만 읽기, HTTPS 외 요청 거부 버킷 정책 |
| API 남용·비용 폭주 NEW | API Gateway 스테이지·메서드 스로틀, 플러그인 사용량 계획, Lambda 예약 동시성 10 |

## 6. 기능 요구사항

모든 검사는 detector.py 의 규칙 하나로 통일해, 웹·확장프로그램·플러그인이 같은 탐지 규칙을 쓴다.

| ID | 기능 | 구성 | 우선순위 |
|---|---|---|---|
| F1 | QR 파일 전송 변경 | Presigned POST 직접 업로드 + DynamoDB 전송 기록 + 다운로드 페이지 QR | P0 |
| F2 | 민감정보 탐지 API | 정규식 + 체크섬, /api/scan , /api/scan/file (4MB) | P0 |
| F3 | 크롬 확장 유출 차단 | Manifest V3, 한 사이트 지원 | P0 |
| F4 | AI 플러그인 | scan_text , create_transfer (OpenAPI 또는 MCP 중 하나), API Key | P1 |
| F5 | 공통 웹 UI | 업로드, QR, 다운로드 페이지, 오류 표시 (CloudFront 배포). 로그인 화면 없음 | P0 |
| F6 | 차단·전송 로그 | DynamoDB sd_events , 유형·시간만 저장, 관리자 콘솔에서 조회 | P1 |
| F7 | 민감정보 정제 | 마스킹·삭제 처리본 생성, 재검사, 미리보기 승인 | P0 |
| F8 | SecureGuard 해결 도우미 | 탐지 설명, 조치 선택 버튼, 요청 해석 | P1 |
| F9 | 사용자 로그인 (삭제) | v1.3에서 제외. 사용자는 로그인 없이 사용, 전송 관리는 관리 토큰(F1). 관리자 로그인은 F13 | — |
| F10 | 다중 파일 전송 NEW | 한 전송에 최대 5개, 합계 20MB | P2 선택 |
| F11 | 내 전송 목록 NEW | 브라우저 localStorage에 전송 ID·관리 토큰 보관, 남은 시간·폐기 | P2 선택 |
| F12 | 브라우저 E2EE NEW | Web Crypto AES-256-GCM, 키는 URL 프래그먼트 | P2 선택 |
| F13 | 운영 모니터링·관리자 콘솔 NEW | CloudWatch 로그·대시보드·알람, 관리자 전용 로그인, 관리자 콘솔 | P1 |

### F1. QR 파일 전송 변경

업로드는 2단계다. ① POST /api/transfers 에 파일명·크기·형식·해시·검사 참조( scan_id 또는 sanitize_id )를 보내면, Lambda가 검증 후 전송 레코드

( PENDING_UPLOAD )를 만들고 5분짜리 Presigned POST를 발급한다. ② 브라우저가 S3에 직접 올린 뒤 POST /api/transfers/{id}/complete 를 호출하면, Lambda가 객 체 존재·크기·해시를 확인하고 ACTIVE 로 바꾼 뒤 공유 링크와 QR을 돌려준다.

Presigned POST 정책에 content-length-range (1B~20MB)와 정확한 객체 키를 넣어 S3 단에서 크기·경로를 강제한다.

만료 시간 기본 10분, 선택지 5분·10분·60분, 상한 60분. 만료는 DynamoDB expires_at 으로 판단한다.

QR에는 S3 주소가 아니라 https://<CloudFront 도메인>/d.html?id=<전송 ID> 를 담는다. 휴대폰이 열면 GET /api/d/{id} 가 상태·만료를 확인하고 5분짜리 Presigned GET을 발급한다. 이렇게 하면 폐기·만료가 즉시 반영되고, 긴 S3 서명 URL이 화면·QR에 노출되지 않는다.

파일 크기 상한 20MB, 허용 형식은 확장자 화이트리스트로 제한한다.

파일 선택 즉시 /api/scan/file 로 검사한다. 민감정보가 있으면 원본 전송을 보류하고 F7·F8 정제 흐름으로 안내한다. 원본 그대로 진행하려면 별도 확인

( acknowledge_risk )을 거친다.

.txt·.csv 외 형식은 "이 형식은 민감정보 검사를 지원하지 않습니다"를 표시하고 사용자 확인( acknowledge_unsupported )이 있어야 전송한다.

"링크 폐기"는 전송 생성 때 받은 관리 토큰( X-Manage-Token )이 맞아야 하며(로그인 없음, F9), DynamoDB 상태를 REVOKED 로 바꾸고 S3 객체를 삭제한다.

S3 객체 키에는 원래 파일명을 쓰지 않는다( transfers/{전송 ID}/0 ). 파일명 자체에 민감정보가 있을 수 있기 때문이며, 다운로드 시 Content-Disposition 으로 원래 이름 을 붙인다.

### F2. 민감정보 탐지

탐지 대상: 주민등록번호, 휴대전화번호, 이메일, AWS Access Key( AKIA… ), 일반 API Key·토큰 패턴, 카드번호.

응답은 탐지 유형과 개수만 반환하고 원문·위치는 반환·저장하지 않는다. 주민등록번호는 체크섬으로 오탐을 줄인다.

/api/scan : 텍스트 최대 50,000자.

/api/scan/file : .txt·.csv를 multipart로 받아 같은 규칙으로 검사. 응답은 파일명·유형·개수와 scan_id . 서버는 결과·SHA-256만 sd_sessions (TTL 10분)에 저장. 파일 상한 4MB 변경, 초과 시 413.

### F3. 크롬 확장 유출 차단

ChatGPT 또는 Claude 웹 입력창 중 한 곳을 대상으로, 전송 버튼 클릭·Enter 입력을 가로채 텍스트를 /api/scan 으로 검사한다. /api/scan 은 아무것도 저장하지 않으므로 로그인 없이 호출할 수 있게 열어 두고 스로틀로 보호한다.

감지 시 전송을 막고 "사내 기밀/개인정보 입력이 감지되어 차단되었습니다" 팝업과 "안전하게 전송하기" 링크(CloudFront 웹)를 띄운다.

차단 시 유형과 시간만 POST /api/ext/logs 로 보낸다. 확장 로그는 사용자 구분 없이 sd_events 에 source=extension 으로 저장되고, 관리자 콘솔에서 본다.

서버가 응답하지 않으면 전송을 막는 쪽(fail-closed)을 기본으로 하되, 설정으로 바꿀 수 있다. 확장 패키지는 CloudFront에서 zip으로 배포하고 개발자 모드로 설치한다.

### F4. AI 플러그인

scan_text : POST /api/plugin/scan . 텍스트 검사 결과(유형·개수)를 반환한다. 읽기 전용, 승인 불필요.

create_transfer : POST /api/plugin/transfers . 4MB 이하 파일(또는 텍스트)을 받아 Lambda가 먼저 검사하고, 민감정보가 있으면 409 SENSITIVE_DETECTED 로 거부 한다. 통과하면 S3에 저장하고 링크와 QR을 반환한다. 호출 전 사용자 승인 단계를 둔다.

API Gateway API Key + 사용량 계획으로 호출 횟수를 제한한다(초당 0.5회 ≈ 분당 30회, 버스트 5, 일 2,000회). API Key는 사용량 식별 수단이지 강한 인증이 아니므로, 데 모용 단일 키로 한정하고 향후 OAuth로 바꾼다.

AI가 임의로 파일을 목록 조회·다운로드하는 도구는 만들지 않는다. 연동이 막히면 Swagger UI( /prod/docs ) 시연으로 대체한다.

### F5. 공통 UI

업로드(+SecureGuard 패널) / QR 결과 / 다운로드 페이지( d.html , 휴대폰용) / 내 전송 목록(선택) / 관리자 콘솔( admin.html , 관리자 로그인 필요) 화면. 일반 사용자 화면에는 로그인이 없다. 모든 정적 파일은 CloudFront로 HTTPS 배포한다. 요청 중 로딩 표시, 오류 시 사용자용 메시지 표시.

### F6. 차단·전송 로그

저장 항목: 시각, 이벤트 종류(BLOCK·SCAN·SANITIZE·TRANSFER·DOWNLOAD·REVOKE), 탐지 유형, 출처(extension·web·plugin). 원문과 파일 내용, 파일명은 저장하지 않는다.

저장소는 DynamoDB sd_events 로 확정 변경. 30일 TTL.

웹 이벤트는 Lambda가 각 API 처리 중 직접 기록한다(브라우저가 로그를 따로 보내지 않음).

### F7. 민감정보 정제

지원 조치: ① 마스킹, ② 해당 항목 삭제, ③ 전송 취소. 원본은 변경하지 않고 별도 처리본을 만든다.

마스킹 형식: 주민등록번호 900101-1****** , 휴대전화번호 010-****-5678 , API Key·토큰은 [REDACTED] 로 치환.

actions 가 비어 있으면 422 VALIDATION_ERROR .

재검사: 처리본을 같은 규칙으로 다시 검사한다. 잔여 민감정보가 있으면 추가 조치 또는 명시적 확인 없이는 전송하지 않는다.

미리보기 승인: 처리본 상위 20행을 보여주고, 승인해야 F1 단계로 넘어간다.

처리본 보관 변경: Lambda는 요청이 끝나면 메모리가 사라지므로, 처리본(최대 4MB)은 응답에 담아 브라우저로 돌려준다. 서버는 sanitize_id , 처리본 SHA-256, 재검사 결과만 sd_sessions (TTL 10분)에 남긴다. 업로드 후 /complete 가 이 해시로 처리본이 바뀌지 않았는지 확인한다.

지원 파일: .txt, .csv. 성능 목표는 1MB CSV 기준 3초 이내.

### F8. SecureGuard 해결 도우미

탐지 결과를 설명하고, 조치를 버튼으로 제시하며, 자연어 요청을 정해진 조치로 해석한다.

해석 결과는 MASK , DELETE , CANCEL , CLARIFY 와 대상 유형 목록만 허용한다.

챗봇은 파일 내용을 읽거나 수정하지 않고, 차단·허용 판단에도 관여하지 않는다. 파일명·유형·개수만 전달받는다.

구현 단계: ① 규칙 기반 문구 + 선택 버튼(필수), ② 키워드 매칭 해석 → 시간이 되면 LLM 보조.

### F9. 사용자 로그인 (삭제) 변경

일반 사용자는 로그인하지 않는다. 가입·아이디·비밀번호를 받지 않으므로 개인정보를 다루는 범위가 줄고, PC에서 바로 쓰는 데모 흐름도 짧아진다. 대신 다음 두 가지로 "자기 전 송만 관리"를 보장한다.

관리 토큰: POST /api/transfers 응답에 256비트 무작위 manage_token 이 한 번만 담긴다. 서버( sd_transfers )에는 SHA-256 해시만 저장한다. /complete , 상태 조회, 폐기는 X-Manage-Token 헤더가 맞아야 하며 틀리면 403.

검사·정제 세션: scan_id · sanitize_id 는 추측 불가한 128비트 난수이고 10분 뒤 만료되므로, 따로 소유자를 묶지 않는다.

관리 토큰을 잃어버리면(탭 종료 등) 그 전송은 직접 폐기할 수 없지만, 만료(최대 60분)와 S3 자동 삭제(1일)로 정리된다. 급하면 관리자가 강제 폐기한다.

로그인은 관리자만 한다. 내용은 F13에 있다.

### F10~F12. 선택 기능 선택

F10 다중 파일 전송: 한 전송 레코드에 items[] (최대 5개, 합계 20MB). 파일별로 검사하고, Presigned POST를 파일 수만큼 발급. 다운로드 페이지는 목록을 보여준다.

F11 내 전송 목록: 로그인이 없으므로 서버 목록 API를 두지 않는다. 이 브라우저에서 만든 전송의 ID·관리 토큰·만료 시각을 localStorage에 저장해 목록, 남은 시간, 폐기 버 튼을 보여준다. 브라우저 데이터를 지우거나 다른 기기에서는 목록이 보이지 않는다(전송 자체는 만료로 정리됨). 저장소 접근은 try/catch로 감싸 실패해도 전송 기능은 동작하 게 한다. 계정 기반 개인 클라우드는 향후 계획.

F12 브라우저 E2EE: 승인된 파일을 Web Crypto API로 AES-256-GCM 암호화(256비트 무작위 키, 12바이트 IV). 키는 공유 링크의 프래그먼트( #k=… )에만 들어가며, 프래그 먼트는 HTTP 요청에 포함되지 않으므로 CloudFront·API Gateway·S3 로그에 남지 않는다. 휴대폰 브라우저가 암호문을 받아 복호화한다. QR을 가진 사람은 키도 가진다는 점, 검사 단계에서는 서버가 평문을 본다는 점을 한계로 명시한다.

### F13. 운영 모니터링 · 관리자 콘솔 NEW

모니터링 (CloudWatch)

Lambda·API Gateway 로그를 CloudWatch Logs에 14일 보존.

대시보드 1개( SecureDrop-Demo ): 호출 수·오류·지연, 차단 건수(유형별), 전송 생성 수.

알람 2개(Lambda 오류, API 5XX). 알림 발송(SNS·SES)은 범위 밖이며 콘솔 상태로만 확인한다.

관리자 전용 로그인 (자체 인증)

이 제품에서 로그인하는 사람은 관리자뿐이다. 가입 API는 없고, 관리자 계정(1~3개)은 infra/create_admin.py 로만 만든다.

DynamoDB sd_admins 에 아이디와 해시된 비밀번호만 저장한다. 해시는 파이썬 표준 라이브러리 hashlib.scrypt (N=217, r=8, p=1, 계정별 16바이트 솔트), 비교는

hmac.compare_digest .

POST /api/admin/login 이 성공하면 256비트 관리자 세션 토큰을 발급하고, sd_admin_sessions 에는 토큰의 SHA-256 해시만 저장한다(유효 8시간). POST

/api/admin/logout 은 세션을 즉시 삭제한다.

5회 실패 시 15분 잠금, 로그인 API 초당 1회(버스트 5) 스로틀, 없는 아이디와 틀린 비밀번호에 같은 오류 문구. 선택: API Gateway 리소스 정책으로 /api/admin/* 를 팀 IP 에서만 허용.

관리자 콘솔 ( admin.html )

현황: 오늘·최근 7일 이벤트 집계(차단·정제·전송·다운로드·폐기, 탐지 유형별, 출처별).

최근 이벤트: 시각·이벤트·유형·출처 목록(F6 로그). 확장 차단 로그도 여기서 본다.

활성 전송: 전송 ID 앞 8자, 크기, 생성·만료 시각, 다운로드 수, 상태, 암호화 여부. 파일명·내용·다운로드 링크는 보여주지 않는다(원칙 4).

강제 폐기: 의심스러운 전송을 즉시 REVOKED 로 바꾸고 S3 객체 삭제. 폐기 이벤트에 source=admin 을 남긴다.

CloudWatch 대시보드로 가는 링크(AWS 콘솔 로그인 필요)를 둔다.

## 7. 비기능 요구사항

| 항목 | 요구사항 |
|---|---|
| 성능 | /api/scan 1초 이내(웜 상태, 확장 차단 체감 기준). /api/scan/file 2초 이내(4MB). 정제 3초 이내(1MB CSV). 선택부터 QR 표시까지 20MB 기준 10 초 이내(S3 직접 업로드). 콜드 스타트는 3초 이내를 허용하되 시연 전 예열 호출 |
| 보안 (S3) | 퍼블릭 액세스 전체 차단, SSE-S3 기본 암호화, HTTPS 외 요청 거부, 버전 관리 끔, 접근은 Presigned URL로만 |
| 보안 (IAM) | Lambda 실행 역할에 파일 버킷 s3:PutObject/GetObject/DeleteObject , 테이블 5개 항목 단위 권한, 로그 쓰기만 허용 (10.9 정책) |
| 보안 (인증) | 일반 사용자 API는 로그인 없이 공개하되 스로틀 적용. 전송 조회·완료·폐기는 관리 토큰 필요(틀리면 403). /api/admin/* 는 관리자 세션 필수(FastAPI 공 통 의존성). 관리자 비밀번호는 scrypt 해시만 저장. 서버에 원문 토큰을 저장하지 않음 |
| 보안 (링크) | 공유 링크 만료 최대 60분, S3 Presigned URL은 업로드·다운로드 모두 5분. 객체는 수명 주기 규칙으로 1일 후 자동 삭제 |
| 보안 (플러그인) | API Key + 사용량 계획(분당 약 30회), 사용자 승인 후에만 전송 도구 실행 |
| 보안 (웹) | CloudFront 응답 헤더 정책: HSTS, X-Content-Type-Options, X-Frame-Options, CSP( connect-src 는 API·S3 도메인만) |
| CORS | API·S3 모두 CloudFront 도메인과 확장 origin만 허용(개발 중에는 localhost:5500 추가) |
| 입력 검증 | 전송 파일 20MB, 검사·정제 파일 4MB, 확장자 화이트리스트, 텍스트 50,000자, 만료 시간 상한, 다중 파일 5개 |
| 오류 처리 | 검증 실패, 인증 실패, 권한 없음, 용량 초과, 만료, 업로드 미완료, 무결성 불일치, S3 오류를 구분해 HTTP 코드와 메시지로 반환 |
| 로깅 | 이벤트 종류, 탐지 유형, 시각, 출처, 요청 ID만 기록. 민감정보 원문·파일 내용·파일명·Presigned URL·관리 토큰·관리자 세션 토큰·비밀번호·챗봇 대화 원문은 기록하지 않음. 요청 본문 로깅 금지 |
| 가용성·비용 | 단일 리전, 서버리스 기본 가용성. Lambda 예약 동시성 10, DynamoDB 온디맨드 |
| 호환성 | 최신 Chrome/Edge(Manifest V3), Lambda Python 3.12, 휴대폰 최신 Safari·Chrome(Web Crypto 지원) |

## 8. 시스템 아키텍처 및 기술 스택 변경

웹 UI, 크롬 확장, AI 플러그인이 모두 API Gateway를 거쳐 하나의 Lambda(FastAPI)로 들어가고, 같은 탐지 규칙을 쓴다. 정적 화면은 CloudFront, 인증은 Lambda 자체 처리 (사용자·세션은 DynamoDB), 파일 바이트는 S3, 상태·이력은 DynamoDB, 로그·지표는 CloudWatch가 맡는다. 대용량 파일은 Lambda를 통과하지 않고 브라우저와 S3가 직접 주고받는다.

### 8.1 AWS 서비스 6개의 역할

| 서비스 | 이 제품에서 하는 일 | 하지 않는 일 / 경계 |
|---|---|---|
| CloudFront | 웹 UI·다운로드 페이지·확장 zip을 HTTPS로 배포, 보안 헤더 부착 | API 프록시로 쓰지 않음(API는 API Gateway 주소 직접 호출). 사용자 지정 도메인은 범위 밖 |
| API Gateway | 경로별 접근 구분(공개/API Key), 스로틀(관리자 로그인 포함), 사용량 계획, CORS 오류 응답, 액세스 로그 | 비즈니스 판단 없음. 모든 경로는 같은 Lambda로 프록시 |
| Lambda | FastAPI 앱 실행: 관리 토큰·관리자 세션 검사, 관리자 집계, 탐지·정제·해석, Presigned 발급, 전송 상태 관리, QR 생성, 이벤트 기록 | 20MB 파일 본문을 받지 않음(검사·정제용 4MB 이하만) |

S3 파일 버킷(전송 객체), 웹 버킷(정적 파일) 메타데이터·이력 저장 안 함. 퍼블릭 접근 없음

DynamoDB 관리자 계정(아이디·비밀번호 해시), 관리자 세션, 전송 세션·검사/정

비밀번호·토큰 원문, 파일 내용·원문은 저장 안 함

제 세션·이벤트 로그

CloudWatch Lambda·API 로그, 대시보드, 알람, 사용자 정의 지표 알림 발송 없음. 요청 본문 기록 안 함

### 8.2 요청 경로와 인증 NEW

> 아키텍처 그림은 원본 PDF를 참고한다.

*그림 1. 요청 경로와 인증 방식. 한 Lambda가 모든 경로를 처리한다. 공개·API Key 구분과 스로틀은 API Gateway가, 관리 토큰·관리자 세션 검사는 Lambda(FastAPI)가 맡는다. 일반 사용자 경로에는 로그*

인이 없다.

API Gateway는 더 구체적인 경로를 먼저 매칭하므로, 공개 리소스( /api/scan , /api/d/{id} , /api/admin/login 등)와 플러그인 리소스( /api/plugin/{proxy+} )를 명시적으 로 만들고, 나머지는 /api/{proxy+} 가 받는다. 이 경로는 API Gateway에서 인증하지 않는다. 대신 FastAPI가 전송 관리 경로에서는 관리 토큰을, /api/admin/* 에서는 관리자 세션을 검사한다. 관리자 라우터는 기본값을 "관리자 세션 필요"로 두어 새 관리자 API가 실수로 공개되지 않게 한다.

REST API를 고른 이유: HTTP API가 더 저렴하고 단순하지만, 플러그인에 필요한 API Key·사용량 계획을 지원하지 않는다. REST API는 API Key·사용량 계획, 메서드별 스로틀, 게이트웨이 오류 응답의 CORS 헤더 설정을 한곳에서 제공한다.

### 8.3 파일 전송 시퀀스 NEW

> 아키텍처 그림은 원본 PDF를 참고한다.

*그림 2. 파일 하나가 선택부터 휴대폰 저장까지 거치는 경로. 실선은 요청, 점선은 응답이다. 20MB 파일 본문은 ⑥과 마지막 다운로드에서만 움직이며 둘 다 S3 직접 통신이다.*

### 8.4 기술 스택

| 계층 | 기술 | 비고 |
|---|---|---|
| 프론트엔드 | HTML, CSS, Vanilla JS | S3 웹 버킷 + CloudFront 배포. 로컬은 python3 -m http.server 5500 |
| 인증 (관리자) NEW | 자체 구현: hashlib.scrypt + secrets 세션 토큰 | 표준 라이브러리만 사용. 관리자 로그인 폼은 admin.html 에 직접 구현. 일반 사용자 로그인 없음 |
| 브라우저 암호화 선택 | Web Crypto API (AES-GCM) | 외부 라이브러리 없음 |
| 크롬 확장 | Manifest V3, JavaScript | content script로 전송 가로채기, 대상 사이트 1곳 |
| 백엔드 변경 | Python 3.12, FastAPI, Mangum | Lambda 핸들러는 Mangum(app) . 로컬은 Uvicorn 포트 8000으로 같은 앱 실행 |
| AWS SDK | boto3 (Lambda 런타임 내장) | S3 Presigned POST/GET, Head/Delete, DynamoDB |
| 저장소 변경 | S3(파일), DynamoDB(상태·로그) | SQLite 선택지 삭제 |
| QR 변경 | segno | 순수 파이썬 PNG 생성. Pillow 같은 네이티브 의존성이 없어 Lambda 패키징이 쉬움 |
| 챗봇 | 규칙 기반 의도 해석 (+ 선택: LLM API) | LLM 사용 시에도 메타정보만 전달, 출력은 고정 조치 값 |
| 플러그인 | OpenAPI( /prod/openapi.json ) 또는 MCP 서버 | 둘 중 하나만 먼저 구현. FastAPI root_path="/prod" 설정 필요 |
| 배포 변경 | AWS CLI 스크립트( infra/ ) | CDK 미사용. 콘솔 작업은 런북에 화면 단위로 기록 |
| 설정 | Lambda 환경 변수 / 로컬 .env | 비밀값 없음(AWS 키·API Key 값은 코드에 두지 않음) |

## 9. API 명세 변경

기본 주소는 https://<api-id>.execute-api.ap-northeast-2.amazonaws.com/prod (로컬은 http://localhost:8000 )이며 모든 응답은 JSON이다. 인증 열의 관리는 전송을 만들 때 받은 관리 토큰( X-Manage-Token ), 관리자는 관리자 세션 토큰( Authorization: Bearer ), Key는 X-API-Key , 공개는 인증 없음(스로틀 적용)이다.

| Method | Endpoint | 인증 | 요청 | 응답 |
|---|---|---|---|---|
| GET | /api/health | 공개 | — | `{"status":"ok","region":"ap-northeast-2"}` |
| POST | /api/scan | 공개 | JSON: `text` (≤50,000자) | `{"blocked":true,"findings":[{"type":"RRN","count":1}]}` |
| POST | /api/scan/file | 공개 | multipart: `file` (.txt·.csv, ≤4MB) | `{"scan_id":"...","blocked":true,"filename":"고객정보.csv","sha256":"...","fi…` |
| POST | /api/sanitize | 공개 | multipart: `file` (≤4MB), `actions` (유형별 MASK/DELETE, 비면 422) | `{"sanitize_id":"...","findings_before":[...],"findings_after":[],"clean":tr…행)","sha256":"...","content_b64":"..."}` |
| POST | /api/assist | 공개 | JSON: `message`, `context` (파일명, 유형·개수) | `{"action":"MASK","targets":["RRN"],"reply":"..."}` |
| POST | /api/transfers **(변경)** | 공개 | JSON: `files[]` (name, size, type, sha256), `scan_id` 또는 `sanitize_id`, `expires_in`, `encrypted`, `acknowledge_risk`, `acknowledge_unsupported` | `{"id":"...","manage_token":"...(1회만 표시)","status":"PENDING_UPLOAD","uplo…{...}}],"upload_expires_in":300}` |
| POST | /api/transfers/{id}/complete **(NEW)** | 관리 | — | `{"id":"...","status":"ACTIVE","share_url":"https://<cf>/d.html?id=...","qr"…` (암호화 시 브라우저가 `#k=` 를 붙여 QR을 다시 그림) |
| GET | /api/transfers/{id} | 관리 | — | `{"id":"...","status":"ACTIVE","expires_at":"...","download_count":0}` |
| DELETE | /api/transfers/{id} | 관리 | — | `{"id":"...","status":"REVOKED"}` |
| GET | /api/d/{id} **(NEW)** | 공개 | — | `{"files":[{"name":"...","size":1234,"url":"(Presigned GET 5분)"}],"encrypte…` |
| POST | /api/ext/logs **(변경)** | 공개 | JSON: `event` (BLOCK), `types[]` | `{"ok":true}` (출처는 서버가 extension으로 고정) |
| POST | /api/admin/login **(NEW)** | 공개 | JSON: `username`, `password` | `{"token":"...","expires_at":"..."}` / 실패 401, 잠김 423 |
| POST | /api/admin/logout **(NEW)** | 관리자 | — | `{"ok":true}` |
| GET | /api/admin/stats **(NEW)** | 관리자 | query: `days` (1~7) | `{"by_event":{"BLOCK":12,"TRANSFER":5},"by_type":{"RRN":9},"by_source":{"ext…` |
| GET | /api/admin/events **(변경)** | 관리자 | query: `limit`, `day` | `{"items":[{"time":"...","event":"BLOCK","types":["RRN"],"source":"extension…` |
| GET | /api/admin/transfers **(NEW)** | 관리자 | query: `status`, `limit` | `{"items":[{"id":"a1b2c3d4…","size":1234,"status":"ACTIVE","created_at":"...","expire…` (파일명 없음) |
| DELETE | /api/admin/transfers/{id} **(NEW)** | 관리자 | — | `{"id":"...","status":"REVOKED"}` (강제 폐기) |
| POST | /api/plugin/scan **(NEW)** | Key | JSON: `text` | `/api/scan` 과 동일 |
| POST | /api/plugin/transfers **(NEW)** | Key | multipart: `file` (≤4MB) 또는 JSON `text`, `expires_in` | `{"id":"...","share_url":"...","qr":"data:image/png;base64,...","expires_at"…` |

> 일부 응답 예시는 원본 PDF의 칸 폭 때문에 중간에서 잘려 있다(…로 표시).

POST /api/transfers 의 서버 검증 순서: ① 크기·확장자·개수 → ② 참조한 scan_id / sanitize_id 가 존재하고 만료 전인지 → ③ 검사 결과에 민감정보가 있으면 sanitize_id (clean) 또는 acknowledge_risk 필요 → ④ 검사 미지원 형식이면 acknowledge_unsupported 필요 → ⑤ 요청 해시와 세션 해시 일치. 이 중 하나라도 실패하면 Presigned POST를 발급하지 않는다.

요청·응답 예시 (응답에 원문은 포함하지 않는다)
```json
// /api/scan 요청
{ "text": "내 번호는 010-1234-5678 이야" }

// 응답
{ "blocked": true, "findings": [ { "type": "PHONE", "count": 1 } ] }

// /api/transfers 응답의 uploads[0]
// → 브라우저는 fields를 그대로 FormData에 넣고 마지막에 file을 붙여 POST
{
  "url": "https://securedrop-files-123456789012.s3.ap-northeast-2.amazonaws.com/",
  "fields": {
    "key": "transfers/<id>/0",
    "Content-Type": "text/csv",
    "x-amz-algorithm": "...",
    "x-amz-credential": "...",
    "x-amz-date": "...",
    "x-amz-security-token": "...",
    "policy": "...",
    "x-amz-signature": "..."
  }
}
```

오류 코드

오류 응답 형식: {"error":{"code":"FILE_TOO_LARGE","message":"..."}} . API Gateway가 직접 거절하는 401·403·429도 게이트웨이 오류 응답 설정으로 같은 형식과

CORS 헤더를 붙인다.

| 코드 | HTTP | 원인 |
|---|---|---|
| VALIDATION_ERROR | 422 | 입력값·확장자·만료 시간 오류, 빈 actions , 확인 플래그 누락 |
| FILE_TOO_LARGE | 413 | 크기 상한 초과 (전송 20MB, 검사·정제·플러그인 4MB) |
| UNAUTHORIZED | 401 | 관리자 세션 토큰·API Key 누락·만료·불일치, 관리자 로그인 실패 |
| ACCOUNT_LOCKED NEW | 423 | 관리자 로그인 5회 실패로 15분 잠김 |
| FORBIDDEN NEW | 403 | 관리 토큰이 해당 전송과 맞지 않음 |
| NOT_FOUND | 404 | 존재하지 않거나 폐기된 전송 |
| EXPIRED | 410 | 만료된 전송 또는 검사·정제 세션 |
| SENSITIVE_REMAINS | 409 | 처리본 재검사에서 민감정보가 남아 있고 사용자 확인이 없음 |
| SENSITIVE_DETECTED NEW | 409 | 플러그인 전송 대상에서 민감정보 탐지 |
| UPLOAD_INCOMPLETE NEW | 409 | /complete 시점에 S3 객체가 없거나 크기가 다름 |
| INTEGRITY_MISMATCH NEW | 409 | 업로드된 객체 해시가 검사·정제 결과 해시와 다름(객체 삭제) |
| UNSUPPORTED_TYPE | 415 | 정제·검사를 지원하지 않는 파일 형식 |
| RATE_LIMITED | 429 | 스로틀·사용량 계획 한도 초과 |
| STORAGE_ERROR | 502 | S3·DynamoDB 호출 실패 |
| INTERNAL_ERROR | 500 | 기타 서버 오류 |

AI 플러그인 도구 매핑

| 도구 | 연결 엔드포인트 | 비고 |
|---|---|---|
| scan_text | POST /api/plugin/scan | 읽기 전용, 승인 불필요 |
| create_transfer | POST /api/plugin/transfers | 호출 전 사용자 승인 필수, 서버가 먼저 검사 |

OpenAPI 방식은 FastAPI가 생성하는 스키마 중 /api/plugin/* 만 남긴 별도 문서를 커스텀 GPT Actions에 연결하고, MCP 방식은 같은 두 함수를 MCP 서버 도구로 노출한다. 두 방식 중 하나만 먼저 구현하며, 플랫폼 연동 절차는 구현 전에 최신 공식 문서로 확인한다.

## 10. AWS 인프라 상세 및 개발 환경 변경

AWS는 별개의 기능이 아니라 제품을 안전하게 운영하는 기반이다. 이 장은 A(AWS/백엔드)가 Day 1에 그대로 따라 만들 수 있는 수준으로 리소스와 설정값을 정한다. 이름의 <acct> 는 AWS 계정 ID다.

### 10.1 리소스 목록

| 서비스 | 리소스 이름 | 핵심 설정 |
|---|---|---|
| S3 | securedrop-files-<acct> | 전송 객체. 10.2 |
| S3 | securedrop-web-<acct> | 정적 웹·확장 zip. CloudFront OAC만 읽기 |
| DynamoDB | sd_admins , sd_admin_sessions , sd_transfers , sd_sessions , sd_events | 온디맨드, TTL 속성 ttl . 10.3 |
| Lambda | securedrop-api | Python 3.12, 1024MB, 25초, 예약 동시성 10. 10.4 |
| IAM | securedrop-api-role | Lambda 실행 역할, 최소 권한. 10.9 |
| API Gateway | securedrop-api (REST, 리전), 스테이지 prod | 사용량 계획 plugin-plan , 메서드 스로틀. 10.5 |
| CloudFront | 배포 1개 ( dxxxx.cloudfront.net ) | OAC, HTTPS 리디렉션, 보안 헤더. 10.7 |
| CloudWatch | 로그 그룹 2개, 대시보드 SecureDrop-Demo , 알람 2개 | 보존 14일. 10.8 |

모든 리소스에 태그 Project=securedrop , Owner=<이름> 를 붙인다. Day 5 정리와 비용 확인을 태그로 한다.

### 10.2 S3

| 설정 | 파일 버킷 securedrop-files-<acct> |
|---|---|
| 퍼블릭 액세스 차단 | 4개 항목 모두 켬. 객체 소유권 BucketOwnerEnforced (ACL 비활성) |

| 암호화 | 기본 암호화 SSE-S3. (KMS는 범위 밖) |
|---|---|
| 버전 관리 | 끔. 폐기·자동 삭제가 실제 삭제가 되도록 |
| 버킷 정책 | aws:SecureTransport = false 인 모든 요청 거부 |
| 수명 주기 | transfers/ 생성 1일 후 만료, 미완료 멀티파트 업로드 1일 후 중단 |
| CORS | AllowedOrigins: CloudFront 도메인(+개발용 http://localhost:5500 ), Methods: GET·POST, Headers: * , ExposeHeaders: ETag , MaxAge 3000 |
| 객체 키 규칙 | transfers/{transfer_id}/{n} . 사용자 계정이 없으므로 키에 사용자 정보가 없다. 원래 파일명은 키에 쓰지 않음 |

```json
// CORS (파일 버킷)
[{
  "AllowedOrigins": ["https://dxxxx.cloudfront.net", "http://localhost:5500"],
  "AllowedMethods": ["GET", "POST"],
  "AllowedHeaders": ["*"],
  "ExposeHeaders": ["ETag"],
  "MaxAgeSeconds": 3000
}]
```

### 10.3 DynamoDB 테이블 설계

다섯 테이블 모두 온디맨드 과금, TTL 속성 이름 ttl (epoch 초). TTL 삭제는 즉시 일어나지 않고 지연될 수 있으므로, 만료 판단은 항상 읽을 때 expires_at 과 현재 시각을 비교 해서 한다. TTL은 청소용이다.

| 테이블 | 키 | 속성 | TTL |
|---|---|---|---|
| sd_admins NEW | PK username | password_hash ( scrypt$N$r$p$salt$hash ), created_at , failed_count , locked_until | 없음(데모 후 테이블 삭제) |
| sd_admin_sessions NEW | PK token_hash (세션 토큰 SHA-256) | username , created_at , expires_at | 만료 시각(8시간) |
| sd_transfers | PK transfer_id GSI day-created-index : created_day + created_at (관리자 목록용) | manage_hash (관리 토큰 SHA-256), status (PENDING_UPLOAD·ACTIVE·REVOKED), files[] (name, size, s3_key, sha256), encrypted , source , scan_ref , created_at , expires_at , download_count | 만료+1일 미완료: 1시간 |
| sd_sessions | PK session_id | kind (SCAN·SANITIZE), findings (유형·개수), sha256 , clean , supported | 생성 10분 후 |
| sd_events | PK day (YYYY-MM-DD) SK ts#uuid | event , types[] , source (web·extension·plugin·admin), request_id | 30일 |

파일명은 sd_transfers 에만(다운로드 페이지 표시용) 저장하고, 전송 레코드와 함께 TTL로 사라진다. 이벤트 로그에는 파일명을 남기지 않는다. 상태 변경은 조건식( ConditionExpression )으로 처리 해 폐기된 전송이 다시 ACTIVE가 되는 경합을 막는다.

### 10.4 Lambda

| 설정 | 값 / 이유 |
|---|---|
| 런타임·아키텍처 | Python 3.12, x86_64 (로컬 빌드 휠과 호환이 쉬움) |
| 핸들러 | handler.handler = Mangum(app, api_gateway_base_path="/prod") |
| 메모리 / 제한 시간 | 1024MB(CPU도 비례 증가, 정제·해시 속도 확보) / 25초(API Gateway 통합 제한 29초보다 짧게) |
| 예약 동시성 | 10. 남용·비용 폭주 상한 겸 데모 규모 |
| 패키징 | zip 배포. 의존성 fastapi , mangum , python-multipart , segno . pydantic-core 가 네이티브라 반드시 Linux 휠로 설치(10.11) |
| 로그 | JSON 한 줄 로그( request_id , 경로, 상태, 지연, 이벤트, 유형). 요청 본문·헤더·쿼리 기록 금지 |
| 콜드 스타트 | 무거운 모듈은 필요한 함수 안에서 import. 시연 5분 전 /api/health 로 예열. 프로비저닝된 동시성은 비용상 쓰지 않음 |

Lambda 환경 변수:

```
APP_ENV=prod
FILES_BUCKET=securedrop-files-<acct>
TABLE_TRANSFERS=sd_transfers
TABLE_SESSIONS=sd_sessions
TABLE_EVENTS=sd_events
TABLE_ADMINS=sd_admins
TABLE_ADMIN_SESSIONS=sd_admin_sessions
ADMIN_SESSION_TTL_SEC=28800
ADMIN_LOGIN_MAX_FAILS=5
ADMIN_LOGIN_LOCK_SEC=900
PUBLIC_BASE_URL=https://dxxxx.cloudfront.net
ALLOWED_ORIGINS=https://dxxxx.cloudfront.net,chrome-extension://<확장 ID>
MAX_FILE_MB=20
SCAN_FILE_MAX_MB=4
MAX_FILES_PER_TRANSFER=5
DEFAULT_EXPIRES_SEC=600
MAX_EXPIRES_SEC=3600
UPLOAD_URL_TTL_SEC=300
DOWNLOAD_URL_TTL_SEC=300
SESSION_TTL_SEC=600
```

AWS_REGION은 Lambda가 자동으로 넣어 준다. 자격 증명 환경 변수나 API Key 값은 넣지 않는다.

### 10.5 API Gateway

유형: REST API, 리전 엔드포인트, 스테이지 prod. 모든 메서드는 Lambda 프록시 통합.

리소스 구성: 공개(메서드 스로틀) — /api/health, /api/scan, /api/d/{id}, /api/ext/logs, /api/admin/login / Key — /api/plugin/{proxy+}(API Key 필수) / 나머지 — /api/{proxy+}(API Gateway 인증 없음, 스테이지 스로틀. FastAPI가 관리 토큰·관리자 세션 검사). 선택: 리소스 정책으로 /api/admin/*를 팀 IP로 제한.

CORS: API Gateway 인가자를 쓰지 않으므로 프리플라이트(OPTIONS)도 Lambda까지 전달되고, FastAPI CORSMiddleware가 응답 헤더를 붙인다. 세션 검사는 OPTIONS 요청을 건너 뛴다.

게이트웨이 오류 응답: DEFAULT_4XX·DEFAULT_5XX에 Access-Control-Allow-Origin과 9장 오류 형식 템플릿 설정. API Key 거절(403)·스로틀(429)이 프론트·확장에서 정상적 으로 읽히게 하기 위함.

바이너리 미디어 유형: multipart/form-data 등록. 파일 본문이 base64로 Lambda에 전달되고 Mangum이 디코딩한다.

스로틀: 스테이지 기본 20 rps / 버스트 40, 공개 메서드 5 rps / 버스트 10, /api/admin/login 1 rps / 버스트 5.

사용량 계획 plugin-plan: 0.5 rps, 버스트 5, 일 2,000회. API Key 1개 연결.

액세스 로그: CloudWatch 로그 그룹 /apigw/securedrop-api. 형식은 requestId, ip, httpMethod, resourcePath, status, responseLatency만(쿼리·헤더 제외).

### 10.6 관리 토큰과 관리자 인증 구현 기준 NEW

Cognito를 쓰지 않고 일반 사용자 로그인도 없으므로, 인증 관련 AWS 리소스는 관리자용 DynamoDB 테이블 2개뿐이다. 구현은 backend/app/services/auth.py 한 파일에 모은다.

```python
# 관리 토큰 (전송 생성 시, 사용자용)
manage_token = secrets.token_urlsafe(32)                      # 응답에 1회만
manage_hash = hashlib.sha256(manage_token.encode()).hexdigest()  # sd_transfers에 저장

# 관리자 비밀번호 해시 (create_admin.py, 표준 라이브러리만 사용)
salt = secrets.token_bytes(16)
dk = hashlib.scrypt(pw.encode(), salt=salt, n=2**17, r=8, p=1, maxmem=256 * 1024 * 1024, dklen=32)
stored = f"scrypt${2**17}$8$1${b64(salt)}${b64(dk)}"
# 검증: 저장된 파라미터로 다시 계산 후 hmac.compare_digest(dk, stored_dk)

# 관리자 세션 토큰
token = secrets.token_urlsafe(32)
put_item(sd_admin_sessions, {sha256(token), username, expires_at, ttl})
```

관리 토큰 비교도 해시끼리 hmac.compare_digest로 한다. 프론트는 관리 토큰을 sessionStorage(F11을 켜면 localStorage)에 두고 X-Manage-Token 헤더로 보낸다.

scrypt 파라미터 N=217은 해시 1회에 약 128MB 메모리를 쓴다. maxmem을 넉넉히 지정하지 않으면 파이썬이 오류를 낸다. 관리자 로그인만 쓰므로 부하는 거의 없다.

관리자 세션 토큰은 admin.html의 sessionStorage에 두고 Authorization: Bearer로 보낸다. 쿠키를 쓰지 않으므로 CSRF 대응이 필요 없다.

관리자 계정은 Day 4에 infra/create_admin.py로 만든다. 이 스크립트와 reset_admin_password.py는 개발자 AWS 프로필로만 실행한다.

테스트 필수 항목: 관리 토큰 없이·다른 토큰으로 폐기 시 403, 관리자 해시가 매번 다른 솔트인지, 틀린 비밀번호·없는 아이디의 문구가 같은지, 5회 실패 잠금, 로그아웃 후 관리자 토큰 401, 관리자 응답에 파일명이 없는지.

### 10.7 CloudFront

원본: securedrop-web-<acct>, OAC(원본 액세스 제어) 사용. 웹 버킷 정책은 이 배포 ARN(AWS:SourceArn)의 s3:GetObject만 허용.

기본 루트 객체 index.html, 뷰어 프로토콜 HTTP → HTTPS 리디렉션, 기본 *.cloudfront.net 인증서 사용(사용자 지정 도메인·ACM은 범위 밖).

캐시: 관리형 CachingOptimized. 배포 스크립트가 업로드 후 무효화(/*) 실행.

응답 헤더 정책: 관리형 보안 헤더 + 사용자 지정 CSP: default-src 'self'; script-src 'self'; connect-src 'self' https://<api-id>.execute-api.ap-northeast-2.amazonaws.com https://securedrop-files- <acct>.s3.ap-northeast-2.amazonaws.com; img-src 'self' data: blob:; frame-ancestors 'none'

배포 경로: /index.html(업로드), /d.html(휴대폰 다운로드), /admin.html(관리자), /download/securedrop-extension.zip.

### 10.8 CloudWatch

로그 그룹: /aws/lambda/securedrop-api, /apigw/securedrop-api. 보존 기간 14일(기본값은 무기한이므로 반드시 설정).

사용자 정의 지표: Lambda가 EMF(임베디드 지표 형식) 로그로 SecureDrop/BlockCount(차원: type, source), SecureDrop/TransferCreated, SecureDrop/SanitizeCount를 남긴다. 별도 API 호출 없이 로그 한 줄로 지표가 생긴다.

대시보드 SecureDrop-Demo: Lambda 호출·오류·지연(p95)·스로틀, API 4XX·5XX·지연, 유형별 차단 건수, 전송 생성 수.

알람: securedrop-lambda-errors(5분간 Errors ≥ 5), securedrop-api-5xx(5분간 5XXError ≥ 5). 알림 대상 없이 상태만 표시.

### 10.9 IAM 최소 권한

Lambda 실행 역할 securedrop-api-role의 인라인 정책. Presigned URL은 서명한 주체의 권한으로 동작하므로, 업로드 URL을 발급하려면 Lambda 역할에 s3:PutObject가 있어야 한 다.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "FilesObjects", "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
      "Resource": ["arn:aws:s3:::securedrop-files-<acct>/transfers/*"]
    },
    {
      "Sid": "Tables", "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
                 "dynamodb:DeleteItem", "dynamodb:Query"],
      "Resource": [
        "arn:aws:dynamodb:ap-northeast-2:<acct>:table/sd_transfers",
        "arn:aws:dynamodb:ap-northeast-2:<acct>:table/sd_transfers/index/*",
        "arn:aws:dynamodb:ap-northeast-2:<acct>:table/sd_sessions",
        "arn:aws:dynamodb:ap-northeast-2:<acct>:table/sd_events",
        "arn:aws:dynamodb:ap-northeast-2:<acct>:table/sd_admins",
        "arn:aws:dynamodb:ap-northeast-2:<acct>:table/sd_admin_sessions"
      ]
    },
    {
      "Sid": "Logs", "Effect": "Allow",
      "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
      "Resource": "arn:aws:logs:ap-northeast-2:<acct>:log-group:/aws/lambda/securedrop-api:*"
    }
  ]
}
```

로그 그룹은 미리 만들어 두므로 logs:CreateLogGroup은 주지 않는다. s3:ListBucket도 주지 않는다(목록은 DynamoDB로 조회). 팀원 콘솔 계정은 개인 IAM 사용 자/Identity Center를 쓰고 루트 계정은 쓰지 않는다.

### 10.10 서비스 한도가 설계에 준 영향 NEW

| 한도·특성 | 설계 결정 |
|---|---|
| Lambda 동기 호출 요청·응답 페이로드 6MB | 20MB 전송은 S3 직접 업로드. 검사·정제·플러그인 파일은 4MB(base64 인코딩 후 약 5.3MB)로 제 한 |
| API Gateway REST 통합 제한 시간 기본 29초, 페이 로드 10MB | Lambda 제한 시간 25초. 긴 작업은 만들지 않음 |
| Presigned URL은 서명에 쓴 임시 자격 증명이 만료되 면 URL 만료 시간 전이라도 무효 | Lambda 역할 자격 증명으로 긴 URL을 만들지 않고, 업로드·다운로드 URL을 필요한 순간에 5분짜리 로 발급. 공유 링크의 60분 만료는 DynamoDB가 관리 |

| Presigned PUT은 업로드 크기를 강제할 수 없음 | Presigned POST + content-length-range 정책 사용 |
|---|---|
| DynamoDB TTL 삭제는 지연됨 | 읽기 시점에 expires_at 비교로 만료 판단 |
| Lambda는 요청 간 메모리를 공유하지 않음 | 정제 세션을 DynamoDB로 이전, 처리본은 브라우저로 반환 |
| scrypt 해시는 메모리를 많이 씀(N=217 ≈ 128MB) | Lambda 1024MB, maxmem 256MB 지정, 관리자 로그인 API 1 rps 스로틀 |
| HTTP API는 API Key·사용량 계획 미지원 | REST API 선택 |
| CloudWatch 로그 기본 보존 무기한 | 14일로 명시 설정 |

### 10.11 배포 절차

CDK 대신 infra/의 AWS CLI 스크립트와 런북으로 재현한다. 스크립트는 여러 번 실행해도 안전하게(이미 있으면 건너뜀) 작성한다. 콘솔에서 만든 API Gateway는 Day 2에 OpenAPI로 내 보내 infra/apigw-export.json에 커밋한다.

| 스크립트 | 하는 일 | 시점 |
|---|---|---|
| 00_env.sh | 계정 ID, 리전, 이름 변수 | Day 1 |
| 10_s3.sh | 버킷 2개, 퍼블릭 차단, 암호화, 수명 주기, CORS, TLS 정책 | Day 1 |
| 20_dynamodb.sh | 테이블 5개 + GSI + TTL 활성화 | Day 1 |
| 30_iam.sh | Lambda 역할 + 10.9 정책 | Day 1 |
| 40_logs.sh | 로그 그룹 2개, 보존 14일 | Day 1 |
| 50_lambda.sh | 함수 생성·환경 변수·예약 동시성 | Day 1~2 |
| 콘솔 런북 infra/RUNBOOK.md | API Gateway 리소스·스로틀·사용량 계획, CloudFront·OAC·헤더 정책, 대시보드·알람 | Day 1~4 |
| deploy_api.sh | Linux 휠로 빌드 → zip → update-function-code | 수시 |
| deploy_web.sh | s3 sync → CloudFront 무효화 | 수시 |
| 99_teardown.sh | 태그 기준 리소스 정리(발표 후) | Day 5 이후 |

```bash
# deploy_api.sh 핵심
pip install -r backend/requirements.txt -t build/ \
  --platform manylinux2014_x86_64 --implementation cp \
  --python-version 3.12 --only-binary=:all:
cp -r backend/app build/ && (cd build && zip -qr ../api.zip .)
aws lambda update-function-code --function-name securedrop-api --zip-file fileb://api.zip

# deploy_web.sh 핵심
aws s3 sync frontend/ s3://securedrop-web-$ACCT --delete
aws cloudfront create-invalidation --distribution-id $DIST_ID --paths "/*"
```

### 10.12 로컬 개발 환경

같은 FastAPI 앱을 로컬에서 Uvicorn으로 실행한다. 관리 토큰·관리자 인증도 앱 안에서 처리하므로 로컬과 배포 환경의 동작이 같다(별도 우회 모드 없음). 로컬에서도 실제 DynamoDB 테 이블을 쓴다.

```bash
# backend/.env (git 제외)
AWS_PROFILE=lab
AWS_REGION=ap-northeast-2
APP_ENV=local
FILES_BUCKET=securedrop-files-<acct>
TABLE_TRANSFERS=sd_transfers
TABLE_SESSIONS=sd_sessions
TABLE_EVENTS=sd_events
TABLE_ADMINS=sd_admins
TABLE_ADMIN_SESSIONS=sd_admin_sessions
PUBLIC_BASE_URL=http://localhost:5500
ALLOWED_ORIGINS=http://localhost:5500,chrome-extension://<확장 ID>

cd ~/securedrop/backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt uvicorn python-dotenv
uvicorn app.main:app --reload --port 8000

# 새 터미널
cd ~/securedrop/frontend && python3 -m http.server 5500
```

크롬 확장은 chrome://extensions에서 개발자 모드를 켜고 extension/ 폴더를 로드한다. 확장의 API 주소는 extension/config.js 한 곳에서 로컬/배포를 전환한다.

### 10.13 비용과 정리

데모 규모(사용자 몇 명, 파일 수십 개)에서는 서버리스 요금이 사용량 기반이라 비용이 매우 작다. 정확한 금액은 Day 5에 콘솔 청구 화면에서 확인하고 발표에 실제 수치로 넣는다.

비용 폭주 방지: Lambda 예약 동시성 10, API 스로틀, 업로드 크기 정책, 객체 1일 자동 삭제, 로그 14일 보존.

발표 후 99_teardown.sh로 CloudFront 비활성화·삭제, 버킷 비우기·삭제, 테이블·함수·API·User Pool 삭제. API Key는 발표 직후 즉시 삭제.

## 11. 디렉터리 구조

```
securedrop/
├── frontend/
│   ├── index.html          # 업로드 / SecureGuard / QR 결과
│   ├── d.html              # (NEW) 휴대폰 다운로드·복호화 페이지
│   ├── admin.html          # (NEW) 관리자 로그인·콘솔
│   ├── my.html             # (NEW, 선택) 내 전송 목록 (localStorage)
│   ├── css/style.css
│   └── js/ config.js · manage.js(NEW, 관리 토큰 보관) · admin.js(NEW) · api.js · upload.js
│           · assist.js · qr.js · crypto.js(NEW, 선택) · download.js(NEW)
├── extension/
│   └── manifest.json · config.js(NEW) · content.js · background.js · popup.html
├── backend/
│   ├── requirements.txt    # fastapi, mangum, python-multipart, segno
│   └── app/
│       ├── main.py · handler.py(NEW, Mangum) · config.py · deps.py(NEW, 관리 토큰·관리자 세션 검사)
│       ├── routers/ admin.py(NEW) · scan.py · sanitize.py · assist.py · transfers.py · download.py(NEW)
│       │            · logs.py(확장 로그 수신) · plugin.py(NEW)
│       └── services/
│           ├── auth.py         # (NEW) 관리 토큰, 관리자 scrypt 해시·세션·잠금
│           ├── detector.py     # 정규식·체크섬 (모든 검사의 단일 규칙)
│           ├── sanitizer.py    # 마스킹·삭제, 재검사 연계
│           ├── intent.py       # 고정 조치 값만 반환
│           ├── storage.py      # (변경) Presigned POST/GET, Head, Delete, 해시
│           ├── repo.py         # (NEW) DynamoDB 5개 테이블 접근
│           ├── metrics.py      # (NEW) EMF 지표 로그
│           └── qr.py           # (변경) segno
├── infra/                  # (NEW) 00~99 스크립트, create_admin.py, reset_admin_password.py, RUNBOOK.md, iam/*.json, apigw-export.json
└── tests/test_cases.md     # 탐지 오탐·미탐, 정제 재검사, 관리자 로그인·잠금, 관리 토큰(403)·만료(410) 케이스
```

## 12. 마일스톤 변경

5일 일정이며 Day 4 저녁에 기능을 동결하고 Day 5는 버그 수정·보안 점검·리허설에만 쓴다. 게이트는 두 개다.

게이트 1 (Day 2 종료): "로그인 없이라도 업로드 → S3 → QR → 휴대폰 다운로드"가 배포 환경에서 한 번 성공해야 한다. 실패하면 선택 기능(F10~F12)을 전부 내려놓는다.

게이트 2 (Day 4 저녁): 기능 동결. 지연 시 잘라내는 순서: E2EE(F12) → 다중 파일(F10) → 내 전송 목록(F11) → 플러그인(F4, Swagger 시연으로 대체).

| 일정 | A — AWS / 백엔드 | B — 보안 / 확장프로그램 | C — 프론트엔드 / 연동 |
|---|---|---|---|
| Day 1 API 계약 · 인 프라 · 기본 화 면 | 10.11 스크립트로 S3·DynamoDB·IAM·로그 그룹 ·빈 Lambda 생성, API Gateway 골격. 9장 API 계약 확정 주도 | detector.py 탐지 규칙·체크섬, /api/scan·/api/scan/file 응답 형식 확정 | 업로드·결과·QR 화면 골격, mock 응답으로 STEP 1~2 |
| Day 2 Lambda 배포 · S3 전송 · QR | Mangum 배포, POST /api/transfers(Presigned POST), /complete, /api/d/{id}, segno QR. API Gateway 내보내기 커밋 | 크롬 확장 뼈대 + /api/scan 연동, sanitizer.py | S3 직접 업로드 연동, d.html 다운로드 화면, CloudFront 배포(웹 버킷·OAC). 게이트 1 |
| Day 3 검사·정제 통합 · 로그 · SecureGuard | 관리 토큰 발급·검사, /api/scan/file·/api/sanitize 배포, DynamoDB 세션·이벤트 기록, 관리 토큰 검사 (403), 해시 비교 | 검사·정제 통합, 확장 차단 팝업 + /api/ext/logs, 재검사 테스트 | SecureGuard 패널(버튼), 관리 토큰 보관과 폐기 버튼, QR 화면 마무리 |
| Day 4 HTTPS 통합 테 스트 · AI 플러 그인 | CloudFront·API 통합 점검, CORS·게이트웨이 오류 응답, IAM 최소 권한 점검, CloudWatch 대시보드·알람, 사용량 계획·API Key, /api/admin/*(관리자 로그인·집계·강제 폐기), create_admin.py | 오탐·미탐 테스트, 관리자 콘솔 화면 (admin.html), 인증 테스트(10.6 필수 항목), 확장 안정화, (여유 시) crypto.js 브라우저 암호화 | 플러그인 도구 2개 연결·승인 단계, /api/assist 자연어 해석, (여유 시) 내 전 송 목록·다중 파일. 게이트 2: 저녁 기능 동결 |

| Day 5 버그 수정 · 리 허설 | 버그 수정, 배포 최종 확인, 비용 확인, 정리 스크립트 점검 | 보안 점검(퍼블릭 차단, 로그에 원문 없음, 키 미포함), 데모 테스트 케이스 | 리허설, 발표 자료, 데모 영상 백업 |
|---|---|---|---|

Day 1에 A·B·C가 확정할 것: 9장 요청·응답 JSON, 4MB·20MB 상한, CloudFront 도메인과 API 주소를 넣을 config.js 위치. 이것이 정해지면 C가 Day 1부터 mock으 로 화면을 만들 수 있다.

## 13. 완료(수용) 기준

기능

파일 업로드 후 QR이 표시되고, 휴대폰 스캔으로 설치·로그인 없이 다운로드된다.

만료 시간이 지난 링크(410)와 폐기한 링크(404)는 접근이 거부된다.

/api/scan이 주민등록번호·전화번호·API Key가 포함된 텍스트를 감지한다.

파일 선택 즉시 /api/scan/file이 호출되고, 민감정보 CSV는 원본 전송이 보류되며 챗봇이 유형·개수를 설명한다.

.txt·.csv 외 형식은 검사 미지원 안내가 표시되고, 사용자 확인 없이는 전송되지 않는다.

선택한 조치가 적용된 처리본이 만들어지고, 재검사되며, 미리보기 승인 후에만 전송된다.

확장프로그램이 대상 AI 사이트에서 민감정보 전송을 막고 팝업을 띄운다.

플러그인(또는 /prod/docs 대체 시연)으로 scan_text, create_transfer가 동작한다.

일반 사용자 화면에는 로그인이 없고, 로그인 없이 검사·정제·전송·폐기가 끝까지 동작한다.

관리자만 admin.html에 로그인해 이벤트 집계·최근 이벤트·활성 전송을 보고 강제 폐기할 수 있다. 화면에 파일명·내용·다운로드 링크가 없다.

sd_admins에는 비밀번호 원문 없이 scrypt 해시만, sd_admin_sessions·sd_transfers에는 토큰 원문 없이 해시만 있다. 관리자 로그인 5회 실패 시 15분 잠긴다.

인프라 NEW

웹은 CloudFront HTTPS 주소로만 접근되고, 웹 버킷의 S3 주소로 직접 접근하면 403이다.

관리 토큰 없이 또는 다른 토큰으로 전송을 조회·폐기하면 403, 관리자 세션 없이 /api/admin/*를 호출하면 401이다.

20MB 파일 업로드가 Lambda를 거치지 않고 S3로 직접 올라간다(브라우저 네트워크 탭으로 확인). 20MB 초과 업로드는 S3가 거부한다.

업로드 후 sd_transfers에 상태가 기록되고, 폐기 시 S3 객체가 삭제된다.

Lambda·API 로그, DynamoDB 어디에도 민감정보 원문·파일 내용·Presigned URL이 없다(로그 그룹 검색으로 확인).

CloudWatch 대시보드에서 시연 중 차단·전송 건수가 올라가는 것이 보인다.

코드 저장소에 AWS 자격 증명과 API Key가 없고, 두 S3 버킷 모두 퍼블릭 액세스 차단이 켜져 있다.

선택 암호화 전송 시 S3에서 받은 객체는 열리지 않는 암호문이고, 휴대폰 브라우저에서는 원본으로 저장된다.

## 14. 리스크와 대응

| 리스크 | 영향 | 대응 |
|---|---|---|
| AI 사이트 UI 변경·DOM 차이 | 확장 가로채기 실패 | 한 사이트만 지원, 선택자는 설정 한 곳에 |
| 플러그인 외부 연동 지연 | Day 3~4 일정 잠식 | Day 4 오후까지 안 되면 Swagger 시연으로 대체 |
| AWS 구성 지연(콘솔 작업 누락) NEW | 배포 불가 | Day 1 스크립트 생성, Day 2 게이트 1, 런북에 설정 화면 단위 기록 |
| CORS·인가자 설정 오류 NEW | 브라우저에서 원인 불명 실패 | 인증 없는 OPTIONS, 게이트웨이 오류 응답에 CORS 헤더, Day 2부터 배포 환 경에서 테스트 |
| Lambda 페이로드 한도 NEW | 큰 파일 검사·정제 413/502 | 4MB 상한, 대용량은 S3 직접 업로드 |
| 콜드 스타트 NEW | 확장 차단이 느리게 체감 | 지연 import, 1024MB, 시연 전 예열 |

| Lambda 패키징 실패(네이티브 휠) NEW | 배포 후 import 오류 | Linux 휠 지정 빌드, segno 사용, Day 2에 첫 배포 |
|---|---|---|
| 관리자 인증 구현 결함 NEW | 관리자 계정 탈취 | 표준 라이브러리(scrypt·secrets·hmac)만 사용, 가입 API 없음, 관리자 화 면에 파일명·내용 미노출, 10.6 테스트 항목 Day 4 점검, 선택적 IP 제한 |
| 관리 토큰 분실 NEW | 사용자가 자기 전송을 폐기 못 함 | 짧은 만료(최대 60분)와 S3 1일 자동 삭제, 관리자 강제 폐기 |
| 정규식 오탐·미탐 | 정상 입력 차단 또는 유출 누락 | 체크섬 검사, 데모용 테스트 케이스로 사전 검증 |
| 범위 과다(정제·챗봇·선택 기능) | 핵심 시나리오 미완성 | 게이트 2의 잘라내기 순서 준수, 챗봇은 버튼 방식 우선 |
| 마스킹 후 문맥상 개인정보 잔존 | 유출 위험 잔존 | 정규식 탐지 유형에 한정함을 UI·발표에 명시, 미리보기 승인 유지 |
| 챗봇의 잘못된 요청 해석 | 의도와 다른 처리 | 처리 전 선택 내용 확인, 고정 조치 값만 허용 |
| 프롬프트 인젝션 | AI가 의도치 않게 파일 전송 | create_transfer 호출 전 사용자 승인, 서버 선검사, 조회·다운로드 도구 미제 공 |
| 확장↔서버 통신 실패 | 차단 판단 불가 | 기본 fail-closed, 설정으로 변경 가능 |
| E2EE 오해 NEW | "서버가 평문을 전혀 못 본다"는 과장 | 검사 단계는 서버가 평문을 본다고 명시. E2EE는 저장·전송 구간 보호로 설명 |
| API Key 유출 NEW | 플러그인 경로 남용 | 사용량 계획 상한, 키는 플러그인 설정에만, 발표 후 즉시 삭제 |

## 15. 향후 계획

Excel·PDF 등 추가 형식의 검사·정제, 브라우저 로컬 검사·마스킹으로 서버 전송 자체를 줄이는 구조

제외한 서비스의 단계적 도입: WAF(공개 API 보호) → KMS(키 관리, E2EE 확장) → EventBridge(정확한 만료 처리) → SQS·Step Functions(대용량 비동기 검사) → SES(알림) → CloudTrail(감사) → CDK(인프라 코드화) → Budgets(비용 알림)

일반 사용자 계정 도입 시 관리형 인증(Cognito 등) 검토, 계정 기반 개인 클라우드, 확장 차단 로그 사용자별 분리, 플러그인 인증을 OAuth로 전환

관리자 MFA·비밀번호 재설정, 관리자 활동 감사 로그

사용자 지정 도메인(ACM), MFA, 1회 다운로드 옵션, 바이러스 검사, 다중 사이트 지원

AWS 보안 설정 점검(퍼블릭 버킷, 과도한 IAM 권한 등)과 챗봇 연계

