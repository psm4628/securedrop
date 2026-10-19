// 브라우저 QR 생성기 (바이트 모드, 오류 정정 M, 버전 1~10, 최대 213바이트).
// E2EE 링크의 키(#k=…)는 서버로 보낼 수 없으므로 서버가 만든 QR 대신 브라우저에서 QR을 다시 그린다.
// 외부 라이브러리 없음(CSP script-src 'self'). 구조는 QR 규격(ISO/IEC 18004)을 그대로 따른다.

// 오류 정정 M: 버전별 [블록당 ECC 바이트, [[블록 수, 블록당 데이터 바이트], ...]]
const BLOCKS = {
  1: [10, [[1, 16]]],
  2: [16, [[1, 28]]],
  3: [26, [[1, 44]]],
  4: [18, [[2, 32]]],
  5: [24, [[2, 43]]],
  6: [16, [[4, 27]]],
  7: [18, [[4, 31]]],
  8: [22, [[2, 38], [2, 39]]],
  9: [22, [[3, 36], [2, 37]]],
  10: [26, [[4, 43], [1, 44]]],
};
const MAX_VERSION = 10;
const FORMAT_BITS_M = 0; // 오류 정정 수준 M의 형식 비트

const bit = (n, i) => ((n >>> i) & 1) === 1;

// ---------------------------------------------------------------- Reed-Solomon (GF(256), 0x11D)

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
for (let i = 0, x = 1; i < 255; i++) {
  EXP[i] = x;
  LOG[x] = i;
  x <<= 1;
  if (x & 0x100) x ^= 0x11d;
}
for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
const gfMul = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);

function generator(degree) {
  let poly = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array(poly.length + 1).fill(0);
    poly.forEach((c, j) => {
      next[j] ^= c;
      next[j + 1] ^= gfMul(c, EXP[i]);
    });
    poly = next;
  }
  return poly; // 최고차항 계수가 1인 degree+1개 계수
}

function eccBytes(data, degree) {
  const gen = generator(degree);
  const rem = new Array(degree).fill(0);
  for (const byte of data) {
    const factor = byte ^ rem.shift();
    rem.push(0);
    for (let i = 0; i < degree; i++) rem[i] ^= gfMul(gen[i + 1], factor);
  }
  return rem;
}

// ---------------------------------------------------------------- 데이터 코드워드

function dataCapacity(version) {
  return BLOCKS[version][1].reduce((n, [count, size]) => n + count * size, 0);
}

function buildCodewords(bytes, version) {
  const countBits = version < 10 ? 8 : 16;
  const bits = [];
  const push = (value, length) => {
    for (let i = length - 1; i >= 0; i--) bits.push((value >>> i) & 1);
  };
  push(0b0100, 4); // 바이트 모드
  push(bytes.length, countBits);
  for (const b of bytes) push(b, 8);
  const capBits = dataCapacity(version) * 8;
  push(0, Math.min(4, capBits - bits.length)); // 종결 비트
  while (bits.length % 8) bits.push(0);
  const data = [];
  for (let i = 0; i < bits.length; i += 8) data.push(parseInt(bits.slice(i, i + 8).join(""), 2));
  for (let pad = 0xec; data.length < dataCapacity(version); pad ^= 0xec ^ 0x11) data.push(pad);

  // 블록으로 나누고 블록별 ECC를 계산한 뒤 교차 배치한다
  const [eccLen, groups] = BLOCKS[version];
  const blocks = [];
  let offset = 0;
  for (const [count, size] of groups) {
    for (let i = 0; i < count; i++) {
      const block = data.slice(offset, offset + size);
      offset += size;
      blocks.push({ data: block, ecc: eccBytes(block, eccLen) });
    }
  }
  const out = [];
  const longest = Math.max(...blocks.map((b) => b.data.length));
  for (let i = 0; i < longest; i++) for (const b of blocks) if (i < b.data.length) out.push(b.data[i]);
  for (let i = 0; i < eccLen; i++) for (const b of blocks) out.push(b.ecc[i]);
  return out;
}

// ---------------------------------------------------------------- 행렬

function alignmentPositions(version) {
  if (version === 1) return [];
  const count = Math.floor(version / 7) + 2;
  const size = version * 4 + 17;
  const step = Math.ceil((version * 4 + 4) / (count * 2 - 2)) * 2;
  const result = [6];
  for (let pos = size - 7; result.length < count; pos -= step) result.splice(1, 0, pos);
  return result;
}

function newMatrix(version) {
  const size = version * 4 + 17;
  const modules = Array.from({ length: size }, () => new Array(size).fill(false));
  const isFunction = Array.from({ length: size }, () => new Array(size).fill(false));
  const set = (x, y, dark) => {
    modules[y][x] = dark;
    isFunction[y][x] = true;
  };

  for (let i = 0; i < size; i++) {
    set(6, i, i % 2 === 0);
    set(i, 6, i % 2 === 0);
  }
  const finder = (cx, cy) => {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const dist = Math.max(Math.abs(dx), Math.abs(dy));
        const x = cx + dx;
        const y = cy + dy;
        if (x >= 0 && x < size && y >= 0 && y < size) set(x, y, dist !== 2 && dist !== 4);
      }
    }
  };
  finder(3, 3);
  finder(size - 4, 3);
  finder(3, size - 4);

  const pos = alignmentPositions(version);
  pos.forEach((px, i) => {
    pos.forEach((py, j) => {
      if ((i === 0 && j === 0) || (i === 0 && j === pos.length - 1) || (i === pos.length - 1 && j === 0)) return;
      for (let dy = -2; dy <= 2; dy++) {
        for (let dx = -2; dx <= 2; dx++) set(px + dx, py + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
      }
    });
  });

  if (version >= 7) {
    let rem = version;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (version << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const a = size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      set(a, b, bit(bits, i));
      set(b, a, bit(bits, i));
    }
  }
  return { size, modules, isFunction, set };
}

function drawFormat(m, mask) {
  const data = (FORMAT_BITS_M << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const bits = ((data << 10) | rem) ^ 0x5412;
  const { size, set } = m;
  for (let i = 0; i <= 5; i++) set(8, i, bit(bits, i));
  set(8, 7, bit(bits, 6));
  set(8, 8, bit(bits, 7));
  set(7, 8, bit(bits, 8));
  for (let i = 9; i < 15; i++) set(14 - i, 8, bit(bits, i));
  for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(bits, i));
  for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(bits, i));
  set(8, size - 8, true); // 항상 어두운 모듈
}

function placeCodewords(m, codewords) {
  const { size, modules, isFunction } = m;
  let i = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? size - 1 - vert : vert;
        if (!isFunction[y][x] && i < codewords.length * 8) {
          modules[y][x] = bit(codewords[i >>> 3], 7 - (i & 7));
          i++;
        }
      }
    }
  }
}

const MASKS = [
  (x, y) => (x + y) % 2 === 0,
  (x, y) => y % 2 === 0,
  (x) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
  (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
];

function applyMask(m, mask) {
  for (let y = 0; y < m.size; y++) {
    for (let x = 0; x < m.size; x++) {
      if (!m.isFunction[y][x] && MASKS[mask](x, y)) m.modules[y][x] = !m.modules[y][x];
    }
  }
}

function penalty(m) {
  const { size, modules } = m;
  let score = 0;
  const lines = [];
  for (let i = 0; i < size; i++) {
    lines.push(modules[i].map((d) => (d ? "1" : "0")).join(""));
    lines.push(modules.map((row) => (row[i] ? "1" : "0")).join(""));
  }
  for (const line of lines) {
    for (const run of line.match(/0+|1+/g)) if (run.length >= 5) score += run.length - 2; // 3 + (len - 5)
    for (const pat of ["00001011101", "10111010000"]) {
      for (let at = line.indexOf(pat); at !== -1; at = line.indexOf(pat, at + 1)) score += 40;
    }
  }
  for (let y = 0; y < size - 1; y++) {
    for (let x = 0; x < size - 1; x++) {
      const c = modules[y][x];
      if (c === modules[y][x + 1] && c === modules[y + 1][x] && c === modules[y + 1][x + 1]) score += 3;
    }
  }
  const dark = modules.reduce((n, row) => n + row.filter(Boolean).length, 0);
  const total = size * size;
  score += Math.floor(Math.abs(dark * 20 - total * 10) / total) * 10;
  return score;
}

// ---------------------------------------------------------------- 공개 API

// 문자열 → 어두운 모듈이 true인 정사각 행렬
export function qrMatrix(text) {
  const bytes = new TextEncoder().encode(text);
  let version = 1;
  for (; version <= MAX_VERSION; version++) {
    const countBits = version < 10 ? 8 : 16;
    if (4 + countBits + bytes.length * 8 <= dataCapacity(version) * 8) break;
  }
  if (version > MAX_VERSION) throw new Error("QR_TOO_LONG");

  const m = newMatrix(version);
  drawFormat(m, 0); // 형식 정보 자리를 먼저 예약해야 데이터가 그 위에 놓이지 않는다
  placeCodewords(m, buildCodewords(bytes, version));
  let best = 0;
  let bestScore = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    applyMask(m, mask);
    drawFormat(m, mask);
    const score = penalty(m);
    if (score < bestScore) {
      best = mask;
      bestScore = score;
    }
    applyMask(m, mask); // 되돌린다
  }
  applyMask(m, best);
  drawFormat(m, best);
  return m.modules;
}

// 문자열 → SVG data URL (img-src 'self' data: 에서 허용). 여백(quiet zone) 4모듈 포함.
export function qrDataUrl(text, scale = 6) {
  const modules = qrMatrix(text);
  const border = 4;
  const n = modules.length + border * 2;
  let path = "";
  modules.forEach((row, y) =>
    row.forEach((dark, x) => {
      if (dark) path += `M${x + border},${y + border}h1v1h-1z`;
    }),
  );
  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" width="${n * scale}" height="${n * scale}" viewBox="0 0 ${n} ${n}" shape-rendering="crispEdges">` +
    `<rect width="${n}" height="${n}" fill="#fff"/><path d="${path}" fill="#000"/></svg>`;
  return "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg);
}
