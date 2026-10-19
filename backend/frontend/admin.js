// 관리자 콘솔. CSP(script-src 'self') 때문에 인라인 스크립트 없이 이 파일만 쓴다.
// 세션 토큰은 sessionStorage에만 둔다(탭을 닫으면 사라짐, 서버 유효기간 8시간). 쿠키 미사용.
// 모든 값은 textContent로만 그려 서버 응답이 HTML로 해석되지 않게 한다.
(() => {
  const config = window.SD_CONFIG || {};
  const API = String(config.adminApiBase ?? config.apiBase ?? "").replace(/\/+$/, "");
  const CW_URL = (window.SD_CONFIG && window.SD_CONFIG.cloudwatchUrl) || "";
  const KEY = "sd_admin_session";
  const $ = (id) => document.getElementById(id);

  const store = {
    get() {
      try {
        const saved = JSON.parse(sessionStorage.getItem(KEY) || "null");
        return saved && typeof saved.token === "string" && saved.token.length > 0 && Date.parse(saved.expires_at) > Date.now() ? saved : null;
      } catch {
        return null;
      }
    },
    set(value) {
      try {
        value ? sessionStorage.setItem(KEY, JSON.stringify(value)) : sessionStorage.removeItem(KEY);
      } catch {
        /* 저장소를 못 써도 현재 탭 동안은 메모리 값으로 동작한다. */
      }
      session = value;
    },
  };
  let session = store.get();

  async function api(path, { method = "GET", body, auth = true } = {}) {
    const requestSession = auth ? session : null;
    const headers = {};
    if (body) headers["Content-Type"] = "application/json";
    if (requestSession) headers.Authorization = "Bearer " + requestSession.token;
    const response = await fetch(API + path, { method, headers, body: body && JSON.stringify(body), cache: "no-store" });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(data?.error?.message || "요청에 실패했습니다.");
      error.status = response.status;
      error.session = requestSession;
      throw error;
    }
    return data;
  }

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }

  function fill(parent, nodes) {
    parent.replaceChildren(...nodes);
  }

  function time(value) {
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? "-" : d.toISOString().replace("T", " ").slice(0, 19);
  }

  function size(bytes) {
    return bytes >= 1048576 ? (bytes / 1048576).toFixed(1) + " MB" : Math.max(1, Math.ceil(bytes / 1024)) + " KB";
  }

  function show(loggedIn) {
    $("login-view").hidden = loggedIn;
    $("console-view").hidden = !loggedIn;
    $("logout").hidden = !loggedIn;
  }

  function expired(error) {
    if (error.status !== 401) return false;
    // 이전 요청의 지연된 401이 새로 로그인한 세션을 지우지 않게 한다.
    if (error.session !== session) return true;
    store.set(null);
    show(false);
    $("login-msg").textContent = "세션이 만료되었습니다. 다시 로그인하세요.";
    return true;
  }

  function kv(list, data) {
    const rows = Object.entries(data).sort((a, b) => b[1] - a[1]);
    fill(list, rows.length ? rows.map(([k, v]) => el("li", k + " · " + v)) : [el("li", "데이터 없음", "muted")]);
  }

  async function loadStats() {
    const stats = await api("/api/admin/stats?days=" + $("days").value);
    const order = ["BLOCK", "SCAN", "SANITIZE", "TRANSFER", "DOWNLOAD", "REVOKE"];
    fill(
      $("by-event"),
      order.map((name) => {
        const card = el("div", undefined, "card");
        card.append(el("strong", stats.by_event[name] || 0), el("span", name));
        return card;
      }),
    );
    kv($("by-type"), stats.by_type);
    kv($("by-source"), stats.by_source);
  }

  async function loadEvents() {
    const { items } = await api("/api/admin/events?limit=50");
    const rows = items.map((row) => {
      const tr = el("tr");
      tr.append(el("td", time(row.time)), el("td", row.event), el("td", (row.types || []).join(", ") || "-"), el("td", row.source));
      return tr;
    });
    if (!rows.length) {
      const tr = el("tr");
      tr.append(Object.assign(el("td", "이벤트 없음", "muted"), { colSpan: 4 }));
      rows.push(tr);
    }
    fill($("events"), rows);
  }

  async function loadTransfers() {
    const { items } = await api("/api/admin/transfers?limit=50&status=" + $("status").value);
    fill(
      $("transfers"),
      items.map((row) => {
        const tr = el("tr");
        const action = el("td");
        if (row.status === "ACTIVE" || row.status === "PENDING_UPLOAD") {
          const button = el("button", "강제 폐기", "danger");
          button.type = "button";
          button.addEventListener("click", () => revoke(row.id, row.display_id));
          action.append(button);
        }
        tr.append(
          el("td", row.display_id),
          el("td", size(row.size)),
          el("td", time(row.created_at)),
          el("td", time(row.expires_at)),
          el("td", row.download_count),
          el("td", row.status),
          el("td", row.encrypted ? "예" : "아니오"),
          action,
        );
        return tr;
      }),
    );
    if (!items.length) {
      const tr = el("tr");
      tr.append(Object.assign(el("td", "전송 없음", "muted"), { colSpan: 8 }));
      fill($("transfers"), [tr]);
    }
  }

  async function revoke(id, shortId) {
    if (!confirm("전송 " + shortId + " 을(를) 강제 폐기합니다. 되돌릴 수 없습니다.")) return;
    try {
      await api("/api/admin/transfers/" + encodeURIComponent(id), { method: "DELETE" });
      $("console-msg").textContent = "전송 " + shortId + " 을(를) 폐기했습니다.";
      await refresh();
    } catch (error) {
      if (!expired(error)) $("console-msg").textContent = error.message;
    }
  }

  async function refresh() {
    if (!session) return;
    try {
      await Promise.all([loadStats(), loadEvents(), loadTransfers()]);
    } catch (error) {
      if (!expired(error)) $("console-msg").textContent = error.message;
    }
  }

  $("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.currentTarget.querySelector('button[type="submit"]');
    if (button.disabled) return;
    button.disabled = true;
    const message = $("login-msg");
    message.textContent = "";
    try {
      const result = await api("/api/admin/login", {
        method: "POST",
        auth: false,
        body: { username: $("username").value.trim(), password: $("password").value },
      });
      $("password").value = ""; // 입력값을 화면에 남기지 않는다.
      store.set(result);
      show(true);
      refresh();
    } catch (error) {
      $("password").value = "";
      message.textContent =
        error.status === 423 ? "계정이 잠겼습니다. 15분 후 다시 시도하세요." : error.status === 429 ? "잠시 후 다시 시도하세요." : error.message;
    } finally {
      button.disabled = false;
    }
  });

  $("logout").addEventListener("click", async () => {
    try {
      await api("/api/admin/logout", { method: "POST" });
    } catch {
      /* 서버 세션이 이미 없어도 로컬 세션은 지운다. */
    }
    store.set(null);
    show(false);
    $("login-msg").textContent = "로그아웃했습니다.";
  });

  $("refresh").addEventListener("click", refresh);
  $("days").addEventListener("change", () => loadStats().catch((e) => expired(e) || ($("console-msg").textContent = e.message)));
  $("status").addEventListener("change", () => loadTransfers().catch((e) => expired(e) || ($("console-msg").textContent = e.message)));

  if (CW_URL) {
    $("cw-link").href = CW_URL;
    $("cw-link").hidden = false;
  }
  show(!!session);
  if (session) refresh();
})();
