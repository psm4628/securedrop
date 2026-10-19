// 브라우저 암호화 (F12, 선택): Web Crypto AES-256-GCM. 외부 라이브러리 없음.
// 형식: [IV 12바이트][암호문 + GCM 태그 16바이트]. 키는 공유 링크의 프래그먼트(#k=…)에만 실린다.
// 프래그먼트는 HTTP 요청에 포함되지 않으므로 CloudFront·API Gateway·S3 로그에 남지 않는다.
// 한계: 검사 단계에서는 서버가 평문을 본다. QR을 가진 사람은 키도 가진다.

export const IV_BYTES = 12;
export const TAG_BYTES = 16;
export const OVERHEAD = IV_BYTES + TAG_BYTES; // 암호문은 평문보다 항상 28바이트 크다

function toBase64Url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(text) {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

// 256비트 무작위 키를 만들고 링크에 넣을 문자열(43자)로 돌려준다.
export async function generateKey() {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  return { key, encoded: toBase64Url(raw) };
}

async function importKey(encoded) {
  let raw;
  try {
    raw = fromBase64Url(encoded);
  } catch {
    throw new Error("BAD_KEY");
  }
  if (raw.length !== 32) throw new Error("BAD_KEY");
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["decrypt"]);
}

// 평문 Blob → 암호문 Blob. 매번 새 IV를 쓴다(같은 키로 IV를 재사용하지 않는다).
export async function encryptBlob(blob, key) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, await blob.arrayBuffer());
  return new Blob([iv, cipher], { type: "application/octet-stream" });
}

// 암호문 ArrayBuffer + 링크의 키 → 평문 Blob.
// 키가 틀렸거나 내용이 바뀌었으면 GCM 태그 검증에서 실패한다(BAD_KEY / CORRUPT).
export async function decryptBuffer(buffer, encodedKey, type = "application/octet-stream") {
  const key = await importKey(encodedKey);
  if (buffer.byteLength < OVERHEAD) throw new Error("CORRUPT");
  const iv = new Uint8Array(buffer, 0, IV_BYTES);
  try {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, new Uint8Array(buffer, IV_BYTES));
    return new Blob([plain], { type });
  } catch {
    throw new Error("CORRUPT");
  }
}

// 공유 링크에 키를 붙인다. URL 객체를 쓰므로 기존 쿼리(?id=…)는 건드리지 않는다.
export function withKey(shareUrl, encodedKey) {
  const url = new URL(shareUrl);
  url.hash = "k=" + encodedKey;
  return url.href;
}

export function keyFromHash(hash) {
  return new URLSearchParams(hash.replace(/^#/, "")).get("k");
}
