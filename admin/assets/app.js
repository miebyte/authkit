(() => {
  "use strict";

  const storageKey = "authkit.admin.token";
  const pageSize = 20;
  const $ = (id) => document.getElementById(id);
  const els = {
    loading: $("loading-screen"), login: $("login-screen"), dashboard: $("dashboard"),
    loginForm: $("login-form"), email: $("login-email"), code: $("login-code"),
    sendCode: $("send-code"), loginSubmit: $("login-submit"), loginFeedback: $("login-feedback"),
    adminName: $("admin-name"), refresh: $("refresh-button"), logout: $("logout-button"),
    query: $("account-query"), searchForm: $("search-form"), rows: $("account-rows"),
    resultCount: $("result-count"), empty: $("list-empty"), pageLabel: $("page-label"),
    prev: $("prev-page"), next: $("next-page"),
    detail: $("detail-dialog"), detailTitle: $("detail-title"), detailContent: $("detail-content"),
    confirm: $("confirm-dialog"), confirmTitle: $("confirm-title"),
    confirmMessage: $("confirm-message"), confirmSubmit: $("confirm-submit"), toast: $("toast"),
  };
  const metrics = {
    accounts: $("metric-accounts"), email_bindings: $("metric-email"),
    wechat_bindings: $("metric-wechat"), active_sessions: $("metric-sessions"),
  };
  let token = sessionStorage.getItem(storageKey) || "";
  let page = 1;
  let query = "";
  let total = 0;
  let listRequest = 0;
  let detailRequest = 0;
  let openAccountId = "";
  let adminId = "";
  let pendingAction = null;
  let toastTimer;

  function setFeedback(message, isError = false) {
    els.loginFeedback.textContent = message;
    els.loginFeedback.classList.toggle("error", isError);
  }

  function showToast(message, isError = false) {
    clearTimeout(toastTimer);
    els.toast.textContent = message;
    els.toast.classList.toggle("error", isError);
    els.toast.hidden = false;
    toastTimer = setTimeout(() => { els.toast.hidden = true; }, 5000);
  }

  function showLogin(message = "") {
    els.loading.hidden = true;
    els.dashboard.hidden = true;
    els.login.hidden = false;
    if (els.detail.open) els.detail.close();
    if (els.confirm.open) els.confirm.close("cancel");
    if (message) setFeedback(message, true);
  }

  function endSession(message) {
    token = "";
    sessionStorage.removeItem(storageKey);
    showLogin(message);
  }

  function showDashboard(account) {
    const name = account?.email || account?.username || account?.id || "管理员";
    adminId = account?.id || "";
    els.adminName.textContent = String(name);
    els.loading.hidden = true;
    els.login.hidden = true;
    els.dashboard.hidden = false;
    setFeedback("");
  }

  async function api(path, { method = "GET", body, auth = true } = {}) {
    const headers = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (auth && token) headers.Authorization = `Bearer ${token}`;
    let response;
    try {
      response = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    } catch {
      throw new Error("网络连接失败，请稍后重试。");
    }
    let data = null;
    if (response.status !== 204) {
      try { data = await response.json(); } catch { /* Empty or non-JSON error response. */ }
    }
    if (!response.ok) {
      if (auth && response.status === 401) endSession("登录已失效，请重新验证邮箱。");
      const errorCode = data?.error;
      const messages = {
        forbidden: "没有权限执行此操作。",
        unauthorized: "登录已失效，请重新验证邮箱。",
        invalid_input: "输入内容有误，请检查后重试。",
        invalid_email: "邮箱地址格式不正确。",
        invalid_code: "验证码无效，请检查后重试。",
        challenge_mismatch: "验证码错误，请检查后重试。",
        challenge_invalid: "验证码已失效，请重新获取。",
        incorrect_code: "验证码错误，请检查后重试。",
        code_invalid: "验证码已失效，请重新获取。",
        resend_too_soon: "发送过于频繁，请稍后重试。",
        too_many_requests: "操作过于频繁，请稍后重试。",
        not_found: "请求的记录不存在或已被移除。",
        last_binding: "不能解除最后一种登录方式。",
        conflict: "当前状态不允许此操作，请刷新后重试。",
        mail_failed: "验证码邮件发送失败，请稍后重试。",
        internal: "服务器暂时无法处理请求，请稍后重试。",
      };
      const message = messages[errorCode] || (typeof errorCode === "string" && !/^[a-z][a-z0-9_]*$/.test(errorCode) ? errorCode : `请求失败（${response.status}）`);
      const error = new Error(message);
      error.status = response.status;
      throw error;
    }
    return data;
  }

  function appendText(parent, tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    node.textContent = text;
    parent.appendChild(node);
    return node;
  }

  function shortId(id) {
    const value = String(id || "");
    return value.length > 20 ? `${value.slice(0, 10)}…${value.slice(-6)}` : value;
  }

  function accountName(account) {
    return account.username || account.email || shortId(account.id) || "未命名账号";
  }

  function formatDate(value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "未知" : new Intl.DateTimeFormat("zh-CN", { dateStyle: "medium", timeStyle: "short" }).format(date);
  }

  function updateMetrics(data) {
    for (const [key, node] of Object.entries(metrics)) {
      const value = data?.[key];
      node.textContent = Number.isFinite(value) ? new Intl.NumberFormat("zh-CN").format(value) : "—";
    }
  }

  async function loadOverview() {
    try { updateMetrics(await api("api/overview")); }
    catch (error) { if (token) { updateMetrics(null); showToast(`概览加载失败：${error.message}`, true); } }
  }

  function setPagination() {
    const pages = Math.max(1, Math.ceil(total / pageSize));
    els.pageLabel.textContent = `第 ${page} / ${pages} 页`;
    els.prev.disabled = page <= 1;
    els.next.disabled = page >= pages;
  }

  function renderRows(items) {
    els.rows.replaceChildren();
    els.empty.hidden = items.length > 0;
    if (!items.length) els.empty.textContent = query ? "没有找到匹配的账号。" : "暂无账号。";
    for (const account of items) {
      const row = document.createElement("tr");
      const nameCell = document.createElement("td");
      appendText(nameCell, "span", "account-name", accountName(account));
      appendText(nameCell, "span", "account-id", shortId(account.id));
      row.appendChild(nameCell);
      appendText(row, "td", account.email ? "" : "muted", account.email || "未绑定");
      const wechatCell = document.createElement("td");
      appendText(wechatCell, "span", `status-pill${account.wechat ? "" : " off"}`, account.wechat ? "已绑定" : "未绑定");
      row.appendChild(wechatCell);
      appendText(row, "td", "count", String(account.active_sessions ?? "—"));
      const actions = document.createElement("td");
      const wrap = appendText(actions, "div", "row-actions", "");
      const detailButton = appendText(wrap, "button", "button button-secondary button-small", "查看详情");
      detailButton.type = "button";
      detailButton.addEventListener("click", () => openDetail(account.id));
      const revokeButton = appendText(wrap, "button", "button button-small button-outline-danger", "撤销会话");
      revokeButton.type = "button";
      revokeButton.disabled = account.active_sessions === 0;
      revokeButton.addEventListener("click", () => confirmRevokeAll(account));
      row.appendChild(actions);
      els.rows.appendChild(row);
    }
  }

  async function loadAccounts() {
    const request = ++listRequest;
    els.resultCount.textContent = "正在加载账号…";
    els.rows.replaceChildren();
    els.empty.hidden = true;
    els.prev.disabled = true;
    els.next.disabled = true;
    const params = new URLSearchParams({ query, page: String(page), limit: String(pageSize) });
    try {
      const data = await api(`api/accounts?${params}`);
      if (request !== listRequest || !token) return;
      total = Number(data?.total) || 0;
      page = Number(data?.page) || page;
      renderRows(Array.isArray(data?.items) ? data.items : []);
      els.resultCount.textContent = `共 ${new Intl.NumberFormat("zh-CN").format(total)} 个账号`;
      setPagination();
    } catch (error) {
      if (request !== listRequest || !token) return;
      els.resultCount.textContent = "账号加载失败";
      els.empty.hidden = false;
      els.empty.textContent = error.message;
      els.pageLabel.textContent = "—";
      showToast(`账号加载失败：${error.message}`, true);
    }
  }

  async function refreshData() {
    els.refresh.disabled = true;
    await Promise.all([loadOverview(), loadAccounts()]);
    els.refresh.disabled = false;
  }

  function detailMetaRow(parent, label, value) {
    const row = appendText(parent, "div", "detail-meta-row", "");
    appendText(row, "span", "", label);
    appendText(row, "strong", "", value);
  }

  function detailSection(parent, title) {
    const section = appendText(parent, "section", "detail-section", "");
    appendText(section, "h3", "", title);
    return section;
  }

  function renderDetail(account) {
    els.detailTitle.textContent = accountName(account);
    const content = els.detailContent;
    content.replaceChildren();
    const meta = appendText(content, "div", "detail-meta", "");
    detailMetaRow(meta, "账号 ID", String(account.id || "—"));
    detailMetaRow(meta, "用户名", account.username || "未设置");
    detailMetaRow(meta, "邮箱", account.email || "未绑定");

    const bindings = detailSection(content, "登录绑定");
    if (!Array.isArray(account.bindings) || account.bindings.length === 0) {
      appendText(bindings, "p", "detail-empty", "暂无绑定信息。");
    } else {
      for (const binding of account.bindings) {
        const item = appendText(bindings, "div", "detail-item", "");
        const main = appendText(item, "div", "detail-item-main", "");
        const isWechat = binding.method === "wechat";
        appendText(main, "strong", "", isWechat ? "微信" : binding.method === "email" ? "邮箱" : String(binding.method || "其他方式"));
        appendText(main, "small", "", isWechat ? "已绑定" : String(binding.identifier || "已绑定"));
        const isOwnBinding = !!adminId && account.id === adminId;
        const isLastBinding = account.bindings.length === 1;
        if (isOwnBinding || isLastBinding) {
          appendText(main, "small", "detail-reason", isOwnBinding ? "超管自己的绑定不可解除" : "最后一种登录方式不可解除");
        }
        const button = appendText(item, "button", "button button-small button-outline-danger", "解除绑定");
        button.type = "button";
        button.disabled = isOwnBinding || isLastBinding;
        button.addEventListener("click", () => confirmDeleteBinding(account, binding));
      }
    }

    const sessions = detailSection(content, "有效会话");
    if (!Array.isArray(account.sessions) || account.sessions.length === 0) {
      appendText(sessions, "p", "detail-empty", "暂无有效会话。");
    } else {
      for (const session of account.sessions) {
        const item = appendText(sessions, "div", "detail-item", "");
        const main = appendText(item, "div", "detail-item-main", "");
        appendText(main, "strong", "", `会话 ${shortId(session.id)}`);
        appendText(main, "small", "", `到期时间：${formatDate(session.expires)}`);
        const button = appendText(item, "button", "button button-small button-outline-danger", "撤销");
        button.type = "button";
        button.addEventListener("click", () => confirmRevokeSession(account, session));
      }
    }
    const footer = appendText(content, "section", "detail-footer", "");
    appendText(footer, "h3", "", "撤销全部会话");
    appendText(footer, "p", "", "让这个账号的所有有效会话立即失效，用户需要重新登录。");
    const button = appendText(footer, "button", "button button-small button-outline-danger", "撤销全部会话");
    button.type = "button";
    button.disabled = account.sessions?.length === 0;
    button.addEventListener("click", () => confirmRevokeAll(account));
  }

  async function openDetail(id) {
    openAccountId = id;
    const request = ++detailRequest;
    els.detailTitle.textContent = "账号详情";
    els.detailContent.replaceChildren();
    appendText(els.detailContent, "p", "detail-message", "正在加载账号详情…");
    if (!els.detail.open) els.detail.showModal();
    try {
      const data = await api(`api/accounts/${encodeURIComponent(id)}`);
      if (request === detailRequest && els.detail.open && openAccountId === id) renderDetail(data);
    } catch (error) {
      if (request === detailRequest && els.detail.open) {
        els.detailContent.replaceChildren();
        appendText(els.detailContent, "p", "detail-message", `加载失败：${error.message}`);
      }
    }
  }

  function askConfirmation(title, message, label, action) {
    pendingAction = action;
    els.confirm.returnValue = "";
    els.confirmTitle.textContent = title;
    els.confirmMessage.textContent = message;
    els.confirmSubmit.textContent = label;
    els.confirm.showModal();
  }

  async function afterMutation(accountId, success) {
    showToast(success);
    await Promise.all([loadOverview(), loadAccounts()]);
    if (els.detail.open && openAccountId === accountId) await openDetail(accountId);
  }

  function confirmRevokeAll(account) {
    askConfirmation("撤销全部会话", `确定撤销“${accountName(account)}”的全部有效会话吗？该账号需要重新登录。`, "全部撤销", async () => {
      await api(`api/accounts/${encodeURIComponent(account.id)}/sessions/revoke`, { method: "POST" });
      await afterMutation(account.id, "已撤销该账号的全部会话。");
    });
  }

  function confirmRevokeSession(account, session) {
    askConfirmation("撤销会话", `确定撤销“${accountName(account)}”的会话 ${shortId(session.id)} 吗？`, "撤销会话", async () => {
      await api(`api/accounts/${encodeURIComponent(account.id)}/sessions/${encodeURIComponent(session.id)}`, { method: "DELETE" });
      await afterMutation(account.id, "会话已撤销。");
    });
  }

  function confirmDeleteBinding(account, binding) {
    const type = binding.method === "wechat" ? "微信" : binding.method === "email" ? "邮箱" : binding.method;
    askConfirmation("解除登录绑定", `确定解除“${accountName(account)}”的${type}绑定吗？这会移除对应登录方式。`, "解除绑定", async () => {
      await api(`api/accounts/${encodeURIComponent(account.id)}/bindings/${encodeURIComponent(binding.method)}`, { method: "DELETE" });
      await afterMutation(account.id, "登录绑定已解除。");
    });
  }

  els.confirm.addEventListener("close", async () => {
    const action = pendingAction;
    pendingAction = null;
    if (els.confirm.returnValue !== "confirm" || !action) return;
    try { await action(); }
    catch (error) { if (token) showToast(error.message, true); }
  });
  els.detail.addEventListener("close", () => { openAccountId = ""; ++detailRequest; });
  $("close-detail").addEventListener("click", () => els.detail.close());

  els.sendCode.addEventListener("click", async () => {
    if (!els.email.reportValidity()) return;
    els.sendCode.disabled = true;
    setFeedback("正在发送验证码…");
    try {
      await api("api/codes", { method: "POST", body: { email: els.email.value.trim() }, auth: false });
      setFeedback("如果该邮箱是超管账号，请查收验证码。");
      els.code.focus();
    } catch (error) { setFeedback(error.message, true); }
    finally { els.sendCode.disabled = false; }
  });

  els.loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!els.loginForm.reportValidity()) return;
    els.loginSubmit.disabled = true;
    setFeedback("正在登录…");
    try {
      const data = await api("api/login", { method: "POST", body: { email: els.email.value.trim(), code: els.code.value.trim() }, auth: false });
      if (!data?.token) throw new Error("登录响应缺少会话凭证。");
      token = data.token;
      sessionStorage.setItem(storageKey, token);
      els.code.value = "";
      showDashboard(data.account);
      await refreshData();
    } catch (error) { if (!token) setFeedback(error.message, true); }
    finally { els.loginSubmit.disabled = false; }
  });

  els.searchForm.addEventListener("submit", (event) => { event.preventDefault(); query = els.query.value.trim(); page = 1; loadAccounts(); });
  els.prev.addEventListener("click", () => { if (page > 1) { --page; loadAccounts(); } });
  els.next.addEventListener("click", () => { if (page * pageSize < total) { ++page; loadAccounts(); } });
  els.refresh.addEventListener("click", refreshData);
  els.logout.addEventListener("click", async () => {
    els.logout.disabled = true;
    try {
      await api("api/logout", { method: "POST" });
      endSession("");
      setFeedback("已退出后台。");
    } catch (error) { if (token) showToast(`退出失败：${error.message}`, true); }
    finally { els.logout.disabled = false; }
  });
  document.querySelectorAll(".nav-link").forEach((link) => link.addEventListener("click", () => {
    document.querySelectorAll(".nav-link").forEach((item) => item.classList.remove("active"));
    link.classList.add("active");
  }));

  (async () => {
    if (!token) { showLogin(); return; }
    try {
      const account = await api("api/me");
      showDashboard(account);
      await refreshData();
    } catch (error) { if (token) endSession(error.message); }
  })();
})();
