// QR 결과 카드 (여정 7): QR, 만료 카운트다운, 다운로드 수, 링크 복사·폐기
// 폐기·상태 조회는 관리 토큰(X-Manage-Token)이 필요하다.
import { api, ApiError } from "./api.js";
import { getToken, removeToken } from "./manage.js";
import { toast } from "./ui.js";

const $ = (id) => document.getElementById(id);
let timer = null;
let current = null;
let onNewHandler = () => {};

// 버튼 리스너는 한 번만 단다 (showTransfer가 여러 번 호출되어도 중복되지 않게)
let bound = false;
function bindOnce() {
  if (bound) return;
  bound = true;
  $("btn-copy").addEventListener("click", copyLink);
  $("btn-revoke").addEventListener("click", revoke);
  $("btn-refresh").addEventListener("click", refreshStatus);
  $("btn-new").addEventListener("click", () => onNewHandler());
}

// transfer: /complete 응답 { id, status, share_url, qr, expires_at }
export function showTransfer(transfer, { onNew }) {
  bindOnce();
  current = transfer;
  onNewHandler = onNew;
  $("qr-img").src = transfer.qr;
  $("qr-e2ee-note").hidden = !transfer.encrypted;
  $("qr-img").classList.remove("is-dead");
  $("qr-status").textContent = "링크 활성 · 다운로드 0회";
  for (const id of ["btn-revoke", "btn-copy", "btn-refresh"]) $(id).disabled = false;
  $("qr-card").hidden = false;
  startCountdown(Date.parse(transfer.expires_at));
}

export function hideTransfer() {
  clearInterval(timer);
  current = null;
  $("qr-card").hidden = true;
}

function startCountdown(expiresAt) {
  clearInterval(timer);
  const tick = () => {
    const left = Math.max(0, Math.floor((expiresAt - Date.now()) / 1000));
    const m = String(Math.floor(left / 60)).padStart(2, "0");
    const s = String(left % 60).padStart(2, "0");
    $("qr-countdown").textContent = `${m}:${s}`;
    if (left === 0) {
      clearInterval(timer);
      markInactive("만료됨 · 더 이상 다운로드할 수 없습니다");
      if (current) removeToken(current.id);
    }
  };
  tick();
  timer = setInterval(tick, 1000);
}

function markInactive(text) {
  $("qr-status").textContent = text;
  $("qr-img").classList.add("is-dead");
  for (const id of ["btn-revoke", "btn-copy", "btn-refresh"]) $(id).disabled = true;
}

async function copyLink() {
  if (!current) return;
  try {
    await navigator.clipboard.writeText(current.share_url);
    toast("링크를 복사했습니다.");
  } catch {
    toast("복사에 실패했습니다.");
  }
}

async function refreshStatus() {
  if (!current) return;
  try {
    const t = await api.getTransfer(current.id, getToken(current.id));
    $("qr-status").textContent = `링크 활성 · 다운로드 ${t.download_count}회`;
  } catch (e) {
    const err = e instanceof ApiError ? e : new ApiError("INTERNAL_ERROR");
    if (err.code === "EXPIRED" || err.code === "NOT_FOUND") {
      clearInterval(timer);
      markInactive(err.code === "EXPIRED" ? "만료됨" : "폐기됨");
    } else {
      toast(err.userMessage);
    }
  }
}

async function revoke() {
  if (!current) return;
  const token = getToken(current.id);
  if (!token) {
    toast("이 탭에 관리 토큰이 없어 폐기할 수 없습니다. 링크는 만료 시 자동으로 정리됩니다.");
    return;
  }
  $("btn-revoke").disabled = true;
  try {
    await api.revokeTransfer(current.id, token);
    removeToken(current.id);
    clearInterval(timer);
    markInactive("폐기됨 · 링크 접근이 차단되었습니다");
    toast("링크를 폐기했습니다.");
  } catch (e) {
    $("btn-revoke").disabled = false;
    toast(e instanceof ApiError ? e.userMessage : "폐기에 실패했습니다.");
  }
}
