// 배포 주소 설정 — 로컬/배포 전환은 이 파일 한 곳에서 한다. (PRD v1.3 §10.12)
// 웹(index.html, d.html)과 관리자 콘솔(admin.html)이 같이 읽는다. 확장의 extension/config.js와 같은 키 이름을 쓴다.
// CSP(script-src 'self') 때문에 인라인 스크립트가 아닌 별도 파일이다. AWS 키·API Key는 넣지 않는다.
window.SD_CONFIG = {
  // API Gateway 주소. 배포: https://<api-id>.execute-api.ap-northeast-2.amazonaws.com/prod
  apiBase: "http://localhost:8000",
  // 배포 시 adminApiBase: ""로 관리자 API를 같은 웹 도메인에서 호출한다.
  // 관리자 콘솔의 CloudWatch 대시보드 링크 (선택, AWS 콘솔 로그인 필요)
  cloudwatchUrl: "",
};
