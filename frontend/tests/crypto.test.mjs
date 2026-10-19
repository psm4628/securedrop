// 실행: cd frontend && node --test tests/crypto.test.mjs   (Node 20+, 빌드·의존성 없음)
import test from "node:test";
import assert from "node:assert/strict";
import { generateKey, encryptBlob, decryptBuffer, withKey, keyFromHash, OVERHEAD, IV_BYTES } from "../js/crypto.js";
import { qrMatrix } from "../js/qrcode.js";

const bytes = async (blob) => new Uint8Array(await blob.arrayBuffer());

test("암호화한 파일은 같은 키로 원본과 똑같이 복호화된다", async () => {
  const plain = new Blob(["이름,전화\n홍길동,010-****-5678\n"], { type: "text/csv" });
  const { key, encoded } = await generateKey();
  const cipher = await encryptBlob(plain, key);
  assert.equal(cipher.size, plain.size + OVERHEAD);
  const back = await decryptBuffer(await cipher.arrayBuffer(), encoded, "text/csv");
  assert.deepEqual(await bytes(back), await bytes(plain));
  assert.equal(back.type, "text/csv");
});

test("암호문에는 평문이 그대로 들어 있지 않다", async () => {
  const secret = "SECRET-MARKER-123456";
  const { key } = await generateKey();
  const cipher = await bytes(await encryptBlob(new Blob([secret.repeat(20)]), key));
  assert.ok(!Buffer.from(cipher).includes(secret));
});

test("같은 파일·같은 키라도 매번 IV가 달라 암호문이 다르다", async () => {
  const { key } = await generateKey();
  const plain = new Blob(["same"]);
  const a = await bytes(await encryptBlob(plain, key));
  const b = await bytes(await encryptBlob(plain, key));
  assert.notDeepEqual(a.slice(0, IV_BYTES), b.slice(0, IV_BYTES));
  assert.notDeepEqual(a, b);
});

test("키가 다르면 복호화가 실패한다", async () => {
  const one = await generateKey();
  const two = await generateKey();
  const cipher = await encryptBlob(new Blob(["hello"]), one.key);
  await assert.rejects(decryptBuffer(await cipher.arrayBuffer(), two.encoded), { message: "CORRUPT" });
});

test("암호문이 한 비트라도 바뀌면 복호화가 실패한다(무결성)", async () => {
  const { key, encoded } = await generateKey();
  const cipher = await bytes(await encryptBlob(new Blob(["hello world"]), key));
  for (const index of [0, IV_BYTES, cipher.length - 1]) {
    const tampered = cipher.slice();
    tampered[index] ^= 1;
    await assert.rejects(decryptBuffer(tampered.buffer, encoded), { message: "CORRUPT" });
  }
});

test("형식이 잘못된 키·너무 짧은 데이터는 거부한다", async () => {
  await assert.rejects(decryptBuffer(new ArrayBuffer(64), "short"), { message: "BAD_KEY" });
  await assert.rejects(decryptBuffer(new ArrayBuffer(64), "!!!!"), { message: "BAD_KEY" });
  const { encoded } = await generateKey();
  await assert.rejects(decryptBuffer(new ArrayBuffer(10), encoded), { message: "CORRUPT" });
});

test("빈 파일도 암호화·복호화된다", async () => {
  const { key, encoded } = await generateKey();
  const cipher = await encryptBlob(new Blob([]), key);
  assert.equal(cipher.size, OVERHEAD);
  assert.equal((await decryptBuffer(await cipher.arrayBuffer(), encoded)).size, 0);
});

test("키는 256비트이며 링크 프래그먼트로만 붙는다", async () => {
  const { encoded } = await generateKey();
  assert.equal(encoded.length, 43); // 32바이트 base64url
  assert.match(encoded, /^[A-Za-z0-9_-]+$/);
  const url = withKey("https://example.cloud/d.html?id=abc", encoded);
  const parsed = new URL(url);
  assert.equal(parsed.search, "?id=abc");   // 서버로 가는 부분에는 키가 없다
  assert.equal(parsed.hash, "#k=" + encoded);
  assert.equal(keyFromHash(parsed.hash), encoded);
  assert.equal(keyFromHash(""), null);
});

test("QR: 실제 공유 링크 길이(키 포함)를 만들 수 있고 너무 길면 거부한다", () => {
  const link = "https://securedrop.ldh.mzsec.cloud/d.html?id=" + "a".repeat(32) + "#k=" + "A".repeat(43);
  const matrix = qrMatrix(link);
  assert.ok(matrix.length >= 21 && matrix.length === matrix[0].length);
  assert.throws(() => qrMatrix("x".repeat(300)), { message: "QR_TOO_LONG" });
});
