// SecureDrop Cloud API 클라이언트 (PRD v1.3 §9)
// - 업로드는 3단계: createTransfer(메타·해시) → uploadToS3(Presigned POST, 브라우저 → S3 직접) → completeTransfer
// - 관리 토큰이 필요한 호출은 manage.js의 토큰을 X-Manage-Token으로 보낸다.
// - CONFIG.USE_MOCK 이면 서버·S3 없이 mock으로 동작한다 (서버 검증 순서·해시 비교까지 흉내).
import { CONFIG } from "./settings.js";

export { CONFIG };

// 탐지 유형 코드 → 화면 라벨 (detector.py TYPES)
export const TYPE_LABELS = {
  RRN: "주민등록번호",
  PHONE: "휴대전화번호",
  EMAIL: "이메일",
  AWS_ACCESS_KEY: "AWS Access Key",
  API_KEY: "API Key·토큰",
  CARD: "카드번호",
};
export const typeLabel = (t) => TYPE_LABELS[t] || t;

// 오류 코드 → 사용자용 메시지 (§9 오류 코드). 서버 message가 있으면 그것을 우선 쓴다.
const ERROR_MESSAGES = {
  VALIDATION_ERROR: "입력값이 올바르지 않습니다.",
  FILE_TOO_LARGE: "파일 크기 상한을 초과했습니다.",
  UNAUTHORIZED: "인증에 실패했습니다.",
  FORBIDDEN: "이 전송을 관리할 권한이 없습니다.",
  NOT_FOUND: "존재하지 않거나 폐기된 링크입니다.",
  EXPIRED: "만료되었습니다.",
  SENSITIVE_REMAINS: "처리본에 민감정보가 남아 있습니다.",
  UPLOAD_INCOMPLETE: "업로드가 완료되지 않았습니다. 다시 시도하세요.",
  INTEGRITY_MISMATCH: "검사한 파일과 업로드된 파일이 달라 전송을 취소했습니다.",
  UNSUPPORTED_TYPE: "민감정보 검사를 지원하지 않는 파일 형식입니다.",
  RATE_LIMITED: "요청이 너무 많습니다. 잠시 후 다시 시도하세요.",
  STORAGE_ERROR: "파일 저장소 오류가 발생했습니다.",
  INTERNAL_ERROR: "서버 오류가 발생했습니다.",
  NETWORK_ERROR: "서버에 연결할 수 없습니다.",
  S3_UPLOAD_FAILED: "파일 업로드에 실패했습니다. 다시 시도하세요.",
};

export class ApiError extends Error {
  constructor(code, message, status, body = null) {
    super(message || ERROR_MESSAGES[code] || "알 수 없는 오류가 발생했습니다.");
    this.code = code;
    this.status = status;
    this.body = body;
  }
  get userMessage() {
    return this.message || ERROR_MESSAGES[this.code];
  }
}

// ---------------------------------------------------------------- 공통 도우미

export const extOf = (name) => (name.split(".").pop() || "").toLowerCase();
export const mimeOf = (file) => file.type || "application/octet-stream";

export async function sha256Hex(blob) {
  const buf = await crypto.subtle.digest("SHA-256", await blob.arrayBuffer());
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function base64ToBlob(b64, type) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new Blob([bytes], { type });
}

async function request(path, { method = "GET", json, form, token } = {}) {
  const opts = { method, headers: {} };
  if (token) opts.headers["X-Manage-Token"] = token;
  if (json !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(json);
  } else if (form) {
    opts.body = form; // multipart 경계는 브라우저가 채운다
  }
  let res;
  try {
    res = await fetch(CONFIG.API_BASE + path, opts);
  } catch {
    throw new ApiError("NETWORK_ERROR", null, 0);
  }
  let body = null;
  try { body = await res.json(); } catch { /* 본문 없음 */ }
  if (!res.ok) {
    const err = body?.error;
    throw new ApiError(err?.code || "INTERNAL_ERROR", err?.message, res.status, body);
  }
  return body;
}

// Presigned POST: fields를 그대로 FormData에 넣고 file은 맨 마지막 (§9 예시)
// fetch는 업로드 진행률을 주지 않으므로 XHR을 쓴다.
function postToS3(upload, blob, onProgress) {
  return new Promise((resolve, reject) => {
    const form = new FormData();
    for (const [k, v] of Object.entries(upload.fields)) form.append(k, v);
    form.append("file", blob);
    const xhr = new XMLHttpRequest();
    xhr.open("POST", upload.url);
    xhr.upload.onprogress = (e) => e.lengthComputable && onProgress?.(e.loaded / e.total);
    xhr.onload = () =>
      xhr.status >= 200 && xhr.status < 300
        ? resolve()
        : reject(new ApiError(xhr.status === 400 ? "FILE_TOO_LARGE" : "S3_UPLOAD_FAILED", null, xhr.status));
    xhr.onerror = () => reject(new ApiError("S3_UPLOAD_FAILED", null, 0));
    xhr.send(form);
  });
}

// ---------------------------------------------------------------- 실제 API

const realApi = {
  health: () => request("/api/health"),

  scanText: (text) => request("/api/scan", { method: "POST", json: { text } }),

  // → { scan_id, blocked, filename, sha256, findings }
  scanFile(file) {
    const form = new FormData();
    form.append("file", file);
    return request("/api/scan/file", { method: "POST", form });
  },

  // actions: [{ action: "MASK" | "DELETE", targets: ["RRN", ...] }]
  // → { sanitize_id, findings_before, findings_after, clean, preview, sha256, content_b64 }
  sanitize(file, actions) {
    const form = new FormData();
    form.append("file", file);
    form.append("actions", JSON.stringify(actions));
    return request("/api/sanitize", { method: "POST", form });
  },

  assist: (message, context) =>
    request("/api/assist", { method: "POST", json: { message, context } }),

  // body: { files: [{name,size,type,sha256}], scan_id | sanitize_id, expires_in, encrypted,
  //         acknowledge_risk, acknowledge_unsupported }
  // → { id, manage_token, status, uploads: [{url, fields}], upload_expires_in }
  createTransfer: (body) => request("/api/transfers", { method: "POST", json: body }),

  uploadToS3: postToS3,

  // → { id, status, share_url, qr, expires_at }
  completeTransfer: (id, token) =>
    request(`/api/transfers/${encodeURIComponent(id)}/complete`, { method: "POST", token }),

  getTransfer: (id, token) => request(`/api/transfers/${encodeURIComponent(id)}`, { token }),

  revokeTransfer: (id, token) =>
    request(`/api/transfers/${encodeURIComponent(id)}`, { method: "DELETE", token }),

  // 휴대폰 다운로드 페이지 → { files: [{name, size, url}], encrypted, expires_at }
  getDownload: (id) => request(`/api/d/${encodeURIComponent(id)}`),
};

// ---------------------------------------------------------------- mock API
// 화면 개발용. 탐지 정규식은 근사치이고(체크섬 없음) 실제 판정은 서버 detector.py가 한다.
// 전송 기록은 d.html(다른 페이지)에서도 보이도록 localStorage에 둔다. 1MB 이하 파일만 내용까지 저장.

const MOCK_PATTERNS = {
  RRN: /\b\d{6}-[1-4]\d{6}\b/g,
  PHONE: /\b01[016789]-?\d{3,4}-?\d{4}\b/g,
  EMAIL: /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g,
  AWS_ACCESS_KEY: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  API_KEY: /\b(?:sk|ghp|xox[bp])[-_][A-Za-z0-9_-]{16,}\b/g,
  CARD: /\b\d{4}-\d{4}-\d{4}-\d{4}\b/g,
};
const MB = 1024 * 1024;
const MOCK_KEY = "sd.mock.transfers";
const delay = (ms) => new Promise((r) => setTimeout(r, ms));
const rid = () => [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("");

function mockDetect(text) {
  const findings = [];
  for (const [type, re] of Object.entries(MOCK_PATTERNS)) {
    const count = (text.match(re) || []).length;
    if (count) findings.push({ type, count });
  }
  return { blocked: findings.length > 0, findings };
}

function utf8ToBase64(text) {
  const bytes = new TextEncoder().encode(text);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

function mockQr(url) {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="220" height="220" viewBox="0 0 220 220">
    <rect width="220" height="220" fill="#fff"/>
    <rect x="10" y="10" width="200" height="200" fill="none" stroke="#111" stroke-width="4" stroke-dasharray="8 6"/>
    <text x="110" y="105" font-family="sans-serif" font-size="22" text-anchor="middle" fill="#111">MOCK QR</text>
    <text x="110" y="135" font-family="sans-serif" font-size="10" text-anchor="middle" fill="#555">d.html?id=${url.split("id=")[1]?.slice(0, 8)}…</text>
  </svg>`;
  return "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg);
}

function mockLoad() {
  try { return JSON.parse(localStorage.getItem(MOCK_KEY)) || {}; } catch { return {}; }
}
function mockSave(all) {
  try { localStorage.setItem(MOCK_KEY, JSON.stringify(all)); } catch { /* 용량 초과 시 무시 */ }
}

const mockSessions = new Map(); // session_id → { kind, sha256, findings, clean, expires }
const mockS3 = new Map();       // key → { size, sha256, dataUrl }

function mockSession(id) {
  const s = mockSessions.get(id);
  if (!s) throw new ApiError("EXPIRED", "검사 결과가 만료되었습니다. 파일을 다시 선택하세요.", 410);
  if (s.expires < Date.now()) throw new ApiError("EXPIRED", "검사 결과가 만료되었습니다. 파일을 다시 선택하세요.", 410);
  return s;
}

async function mockCheckToken(t, token) {
  if (!token || (await sha256Hex(new Blob([token]))) !== t.manage_hash) {
    throw new ApiError("FORBIDDEN", null, 403);
  }
}

const mockApi = {
  async health() {
    await delay(100);
    return { status: "ok", region: "ap-northeast-2", mock: true };
  },

  async scanText(text) {
    await delay(200);
    if (text.length > 50000) throw new ApiError("VALIDATION_ERROR", "텍스트는 50,000자 이하여야 합니다.", 422);
    return mockDetect(text);
  },

  async scanFile(file) {
    await delay(500);
    if (!CONFIG.SCANNABLE_EXTS.includes(extOf(file.name))) throw new ApiError("UNSUPPORTED_TYPE", null, 415);
    if (file.size > CONFIG.SCAN_FILE_MAX_MB * MB) throw new ApiError("FILE_TOO_LARGE", null, 413);
    if (file.size === 0) throw new ApiError("VALIDATION_ERROR", "빈 파일은 처리할 수 없습니다.", 422);
    const result = mockDetect(await file.text());
    const sha256 = await sha256Hex(file);
    const scanId = rid();
    mockSessions.set(scanId, { kind: "SCAN", sha256, ...result, clean: !result.blocked, expires: Date.now() + 600e3 });
    return { scan_id: scanId, filename: file.name, sha256, ...result };
  },

  async sanitize(file, actions) {
    await delay(700);
    if (!Array.isArray(actions) || actions.length === 0) {
      throw new ApiError("VALIDATION_ERROR", "정제 조치를 선택하세요.", 422);
    }
    if (file.size > CONFIG.SCAN_FILE_MAX_MB * MB) throw new ApiError("FILE_TOO_LARGE", null, 413);
    const text = await file.text();
    const before = mockDetect(text).findings;
    let out = text;
    for (const { action, targets } of actions) {
      for (const type of targets) {
        const re = MOCK_PATTERNS[type];
        if (!re) continue;
        out = out.replace(re, (m) => {
          if (action === "DELETE") return "";
          if (type === "RRN") return m.slice(0, 8) + "******";
          if (type === "PHONE") return m.replace(/^(\d{3}-?)\d{3,4}(-?\d{4})$/, "$1****$2");
          return "[REDACTED]";
        });
      }
    }
    const after = mockDetect(out).findings;
    const content = new Blob([out]);
    const sha256 = await sha256Hex(content);
    const sanitizeId = rid();
    mockSessions.set(sanitizeId, { kind: "SANITIZE", sha256, findings: after, clean: after.length === 0, expires: Date.now() + 600e3 });
    return {
      sanitize_id: sanitizeId,
      findings_before: before,
      findings_after: after,
      clean: after.length === 0,
      preview: out.split("\n").slice(0, 20).join("\n"),
      sha256,
      content_b64: utf8ToBase64(out),
    };
  },

  async assist(message, context) {
    await delay(300);
    const all = (context?.findings || []).map((f) => f.type);
    const options = [
      { label: "마스킹", action: "MASK", targets: all },
      { label: "해당 항목 삭제", action: "DELETE", targets: all },
      { label: "전송 취소", action: "CANCEL", targets: [] },
    ];
    if (/취소|그만/.test(message)) return { action: "CANCEL", targets: [], reply: "전송을 취소했습니다.", options };
    const targets = Object.entries(TYPE_LABELS)
      .filter(([, label]) => message.includes(label.slice(0, 4)))
      .map(([code]) => code);
    if (/삭제|지워/.test(message)) return { action: "DELETE", targets, reply: "해당 항목을 삭제하겠습니다.", options };
    if (/가려|마스킹|숨겨/.test(message)) return { action: "MASK", targets, reply: "해당 항목을 마스킹하겠습니다.", options };
    return { action: "CLARIFY", targets: [], reply: "마스킹·삭제·취소 중 어떤 조치를 원하시나요?", options };
  },

  // A의 v1.3 백엔드 검증 순서를 따른다:
  // 개수·크기 → 확장자 → .txt/.csv는 검사·정제 참조 필수 / 그 외는 acknowledge_unsupported
  // → 처리본은 user_approved → 민감정보 남으면 acknowledge_risk (409) → 요청 해시 = 세션 해시 (409)
  async createTransfer(body) {
    await delay(300);
    const { files, scan_id, sanitize_id, expires_in, acknowledge_risk, acknowledge_unsupported, user_approved, encrypted } = body;
    if (![300, 600, 3600].includes(expires_in)) {
      throw new ApiError("VALIDATION_ERROR", "만료 시간은 300, 600, 3600초 중 선택하세요.", 422);
    }
    if (!Array.isArray(files) || files.length !== 1) throw new ApiError("VALIDATION_ERROR", "파일을 하나 선택하세요.", 422);
    const f = files[0];
    if (f.size > CONFIG.MAX_FILE_MB * MB) throw new ApiError("FILE_TOO_LARGE", "전송 파일은 합계 20MiB 이하여야 합니다.", 413);
    if (!CONFIG.ALLOWED_EXTS.includes(extOf(f.name))) throw new ApiError("VALIDATION_ERROR", "허용되지 않는 파일 형식입니다.", 422);

    const ref = sanitize_id || scan_id;
    const s = ref ? mockSession(ref) : null;
    if (CONFIG.SCANNABLE_EXTS.includes(extOf(f.name))) {
      if (!s) throw new ApiError("VALIDATION_ERROR", "검사 또는 정제 참조가 필요합니다.", 422);
    } else if (!acknowledge_unsupported) {
      throw new ApiError("VALIDATION_ERROR", "검사 미지원 형식에 대한 확인이 필요합니다.", 422);
    }
    if (sanitize_id && !user_approved) throw new ApiError("VALIDATION_ERROR", "처리본 미리보기 승인이 필요합니다.", 422);
    if (s && !s.clean && !acknowledge_risk) {
      throw new ApiError("SENSITIVE_REMAINS", "민감정보 정제 또는 위험 확인이 필요합니다.", 409);
    }
    // 암호화 전송은 암호문 해시를 보내므로 검사 세션의 평문 해시와 비교하지 않는다(서버와 동일)
    if (s && !encrypted && s.sha256 !== f.sha256) {
      throw new ApiError("INTEGRITY_MISMATCH", "검사·정제 결과 해시가 일치하지 않습니다.", 409);
    }

    const id = rid();
    const token = rid() + rid();
    const key = `transfers/${id}/0`;
    const all = mockLoad();
    all[id] = {
      id,
      manage_hash: await sha256Hex(new Blob([token])),
      status: "PENDING_UPLOAD",
      files: [{ name: f.name, size: f.size, sha256: f.sha256, s3_key: key }],
      encrypted: !!encrypted,
      expires_at: new Date(Date.now() + expires_in * 1000).toISOString(), // 생성 시점부터 계산
      upload_expires_at: Date.now() + 300e3,
      download_count: 0,
    };
    mockSave(all);
    return {
      id,
      manage_token: token,
      status: "PENDING_UPLOAD",
      uploads: [{ url: "mock://s3", fields: { key, "Content-Type": f.type } }],
      upload_expires_in: 300,
      expires_at: all[id].expires_at,
    };
  },

  async uploadToS3(upload, blob, onProgress) {
    if (blob.size > CONFIG.MAX_FILE_MB * MB) throw new ApiError("FILE_TOO_LARGE", null, 400);
    for (let p = 0.1; p <= 1.001; p += 0.1) {
      await delay(80);
      onProgress?.(Math.min(p, 1));
    }
    let dataUrl = null;
    if (blob.size <= MB) {
      dataUrl = await new Promise((r) => {
        const fr = new FileReader();
        fr.onload = () => r(fr.result);
        fr.readAsDataURL(blob);
      });
    }
    mockS3.set(upload.fields.key, { size: blob.size, sha256: await sha256Hex(blob), dataUrl });
  },

  async completeTransfer(id, token) {
    await delay(300);
    const all = mockLoad();
    const t = all[id];
    if (!t) throw new ApiError("NOT_FOUND", null, 404);
    await mockCheckToken(t, token);
    if (t.status === "REVOKED") throw new ApiError("NOT_FOUND", null, 404);
    if (Date.parse(t.expires_at) <= Date.now()) throw new ApiError("EXPIRED", "만료된 전송입니다.", 410);
    const f = t.files[0];
    const shareUrl = new URL(`d.html?id=${id}`, location.href).href;
    if (t.status === "ACTIVE") {
      // 재시도: 같은 링크를 돌려준다
      return { id, status: "ACTIVE", share_url: shareUrl, qr: mockQr(shareUrl), expires_at: t.expires_at };
    }
    if (t.upload_expires_at <= Date.now()) throw new ApiError("EXPIRED", "업로드 유효 시간이 지났습니다.", 410);
    const obj = mockS3.get(f.s3_key);
    if (!obj || obj.size !== f.size) throw new ApiError("UPLOAD_INCOMPLETE", null, 409);
    if (obj.sha256 !== f.sha256) {
      // 서버는 해시 불일치 시 전송을 폐기하고 객체를 지운다
      mockS3.delete(f.s3_key);
      t.status = "REVOKED";
      mockSave(all);
      throw new ApiError("INTEGRITY_MISMATCH", null, 409);
    }
    t.status = "ACTIVE";
    f.dataUrl = obj.dataUrl;
    mockSave(all);
    return { id, status: "ACTIVE", share_url: shareUrl, qr: mockQr(shareUrl), expires_at: t.expires_at };
  },

  async getTransfer(id, token) {
    await delay(150);
    const t = mockLoad()[id];
    if (!t || t.status === "REVOKED") throw new ApiError("NOT_FOUND", null, 404);
    await mockCheckToken(t, token);
    if (t.expires_at && Date.parse(t.expires_at) < Date.now()) throw new ApiError("EXPIRED", null, 410);
    return { id, status: t.status, expires_at: t.expires_at, download_count: t.download_count };
  },

  async revokeTransfer(id, token) {
    await delay(200);
    const all = mockLoad();
    const t = all[id];
    if (!t) throw new ApiError("NOT_FOUND", null, 404);
    await mockCheckToken(t, token);
    // 서버처럼 이미 폐기된 전송도 재시도 허용
    t.status = "REVOKED";
    delete t.files[0].dataUrl;
    mockS3.delete(t.files[0].s3_key);
    mockSave(all);
    return { id, status: "REVOKED" };
  },

  async getDownload(id) {
    await delay(300);
    const all = mockLoad();
    const t = all[id];
    if (!t || t.status !== "ACTIVE") throw new ApiError("NOT_FOUND", null, 404);
    if (Date.parse(t.expires_at) < Date.now()) throw new ApiError("EXPIRED", null, 410);
    t.download_count += 1;
    mockSave(all);
    return {
      files: t.files.map((f) => ({ name: f.name, size: f.size, url: f.dataUrl || null })),
      encrypted: !!t.encrypted,
      expires_at: t.expires_at,
    };
  },
};

export const api = CONFIG.USE_MOCK ? mockApi : realApi;
