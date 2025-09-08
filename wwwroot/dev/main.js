(() => {
  const $ = (id) => document.getElementById(id);
  const bindClick = (id, handler) => { const el = $(id); if (el) el.onclick = handler; };
  const v = (id) => (document.getElementById(id)?.value ?? '').toString();
  // Tabs
  document.querySelectorAll('nav.tabs button').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('nav.tabs button').forEach(b=>b.classList.remove('active'));
      document.querySelectorAll('section.tab').forEach(s=>s.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(btn.dataset.tab).classList.add('active');
    });
  });
  // Base URL is set in code; no need to configure in UI
  const BASE_URL = (window.location && window.location.origin) || 'https://localhost:7086';
  let base = BASE_URL;
  // No Config UI needed; base is fixed to API origin

  let accessToken = null, refreshToken = null;
  const auth = () => accessToken ? { 'Authorization': 'Bearer ' + accessToken } : {};
  const out = (el, data) => { const node = $(el); if (!node) return; node.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2); };
  const updateAuthUi = () => {
    const cpBtn = document.getElementById('btnChangePassword');
    if (cpBtn) cpBtn.disabled = !accessToken;
  const meBtn = document.getElementById('btnMe');
  if (meBtn) meBtn.disabled = !accessToken;
  const refreshBtn = document.getElementById('btnRefresh');
  if (refreshBtn) refreshBtn.disabled = !refreshToken;
  const logoutBtn = document.getElementById('btnLogout');
  if (logoutBtn) logoutBtn.disabled = !refreshToken;
  const logoutAllBtn = document.getElementById('btnLogoutAll');
  if (logoutAllBtn) logoutAllBtn.disabled = !accessToken;
  };
  updateAuthUi();

  async function call(path, opts = {}) {
    const url = base.replace(/\/$/, '') + path;
    try {
      const res = await fetch(url, { ...(opts || {}), headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) } });
      const text = await res.text();
      try {
        const json = JSON.parse(text);
        return { ok: res.ok, status: res.status, json };
      } catch {
        return { ok: res.ok, status: res.status, text };
      }
    } catch (err) {
      console.error('Request failed', { url, err });
      return { ok: false, status: 0, error: (err && err.message) || String(err), url };
    }
  }

  // Register
  bindClick('btnRegister', async () => {
  const payload = { username: v('regUser'), email: v('regEmail'), password: v('regPass') };
    const r = await call('/api/v1/authenticate/register', { method:'POST', body: JSON.stringify(payload) });
    out('outRegister', r);
  });

  // Login
  bindClick('btnLogin', async () => {
  const payload = { username: v('loginUser').trim(), password: v('loginPass'), mfaCode: v('loginMfa').trim() };
    const r = await call('/api/v1/authenticate/login', { method:'POST', body: JSON.stringify(payload) });
    out('outLogin', r);
  if (r.json && r.json.token) { accessToken = r.json.token; refreshToken = r.json.refreshToken; updateAuthUi(); }
  });

  // Refresh
  bindClick('btnRefresh', async () => {
  if (!refreshToken) { out('outToken', 'no refresh token; login first'); return; }
    const r = await call('/api/v1/authenticate/refresh', { method:'POST', body: JSON.stringify({ refreshToken }) });
    out('outToken', r);
  if (r.json && r.json.token) { accessToken = r.json.token; refreshToken = r.json.refreshToken; updateAuthUi(); }
  });
  // Logout
  bindClick('btnLogout', async () => {
    const r = await call('/api/v1/authenticate/logout', { method:'POST', headers: { ...auth() }, body: JSON.stringify({ refreshToken }) });
    out('outToken', r);
  accessToken = null; refreshToken = null; updateAuthUi();
  });
  // Logout All
  bindClick('btnLogoutAll', async () => {
    const r = await call('/api/v1/authenticate/logout-all', { method:'POST', headers: { ...auth() } });
    out('outToken', r);
  accessToken = null; refreshToken = null; updateAuthUi();
  });
  bindClick('btnCopyToken', async () => { if (accessToken) { await navigator.clipboard.writeText(accessToken); out('outToken', 'token copied'); } else out('outToken', 'no token'); });
  bindClick('btnDecodeToken', () => {
    if (!accessToken) { out('outTokenDecoded', 'no token'); return; }
    const parts = accessToken.split('.');
    if (parts.length < 2) { out('outTokenDecoded', 'invalid token'); return; }
    const payload = JSON.parse(atob(parts[1].replace(/-/g,'+').replace(/_/g,'/')));
    out('outTokenDecoded', payload);
  });
  bindClick('btnChangePassword', async () => {
    if (!accessToken) { out('outChangePassword', 'login first'); return; }
    const r = await call('/api/v1/authenticate/change-password', { method:'POST', headers: { ...auth() }, body: JSON.stringify({ currentPassword: v('cpCurrent'), newPassword: v('cpNew') }) });
    out('outChangePassword', r);
    if (r.ok) {
      // Password change bumps token_version and revokes refresh tokens. Require re-login.
      accessToken = null; refreshToken = null; updateAuthUi();
      out('outChangePassword', 'Password changed. Please login again.');
    }
  });
  // Me
  bindClick('btnMe', async () => {
    if (!accessToken) { out('outToken', 'login first'); return; }
    const r = await call('/api/v1/users/me', { headers: { ...auth() } });
    out('outToken', r);
    if (r.json && (r.json.Id || r.json.id)) {
  const adminEl = $('#adminUserId'); if (adminEl) adminEl.value = r.json.Id || r.json.id;
    }
  });

  // Email flows
  bindClick('btnReqConfirm', async () => {
  const r = await call('/api/v1/authenticate/request-email-confirm', { method:'POST', body: JSON.stringify({ email: v('emailAddr') }) });
  out('outEmail', r);
  });
  bindClick('btnConfirmEmail', async () => {
  const r = await call('/api/v1/authenticate/confirm-email', { method:'POST', body: JSON.stringify({ email: v('emailAddr'), token: v('emailToken') }) });
    out('outEmail', r);
  });
  
  bindClick('btnReqReset', async () => {
  const r = await call('/api/v1/authenticate/request-password-reset', { method:'POST', body: JSON.stringify({ email: v('resetEmail') }) });
  out('outEmail', r);
  });
  bindClick('btnDoReset', async () => {
  const r = await call('/api/v1/authenticate/confirm-password-reset', { method:'POST', body: JSON.stringify({ email: v('resetEmail'), token: v('resetToken'), newPassword: v('resetNew') }) });
    out('outEmail', r);
  });
  

  // Change email
  bindClick('btnChgEmailStart', async () => {
  const r = await call('/api/v1/authenticate/change-email/start', { method:'POST', headers: { ...auth() }, body: JSON.stringify({ newEmail: v('chgNewEmail') }) });
  out('outChangeEmail', r);
  });
  bindClick('btnChgEmailConfirm', async () => {
  const r = await call('/api/v1/authenticate/change-email/confirm', { method:'POST', headers: { ...auth() }, body: JSON.stringify({ newEmail: v('chgNewEmail'), token: v('chgToken') }) });
    out('outChangeEmail', r);
    if (r.ok) {
      // Email change bumps token_version and revokes refresh tokens. Require re-login.
      accessToken = null; refreshToken = null; updateAuthUi();
      out('outChangeEmail', 'Email changed. Please login again.');
    }
  });

  // Revoke specific refresh
  bindClick('btnRevoke', async () => {
  const token = v('revokeToken') || refreshToken;
    const r = await call('/api/v1/authenticate/revoke-refresh', { method:'POST', body: JSON.stringify({ refreshToken: token }) });
    out('outRevoke', r);
  });

  // MFA
  bindClick('btnMfaStart', async () => { const r = await call('/api/v1/authenticate/mfa/enroll/start', { method:'POST', headers: { ...auth() } }); out('outMfa', r); });
  bindClick('btnMfaQr', async () => {
    if (!accessToken) { out('outMfa', 'login first'); return; }
    const url = base.replace(/\/$/, '') + '/api/v1/authenticate/mfa/qr';
    const res = await fetch(url, { headers: { ...auth() } });
    if (res.ok) {
      const blob = await res.blob();
      const img = document.createElement('img');
      img.src = URL.createObjectURL(blob);
      const pre = document.createElement('div');
      pre.appendChild(img);
    const cont = document.getElementById('outMfa');
    if (cont) { cont.textContent = ''; cont.appendChild(pre); }
    } else { out('outMfa', { status: res.status, text: await res.text() }); }
  });
  bindClick('btnMfaConfirm', async () => { const r = await call('/api/v1/authenticate/mfa/enroll/confirm', { method:'POST', headers: { ...auth() }, body: JSON.stringify({ code: v('mfaCode') }) }); out('outMfa', r); });
  bindClick('btnMfaDisable', async () => { const r = await call('/api/v1/authenticate/mfa/disable', { method:'POST', headers: { ...auth() } }); out('outMfa', r); });
  bindClick('btnMfaRegen', async () => { const r = await call('/api/v1/authenticate/mfa/recovery/regenerate', { method:'POST', headers: { ...auth() } }); out('outMfa', r); });

  // Misc
  bindClick('btnJwks', async () => { const r = await call('/.well-known/jwks.json'); out('outMisc', r); });
  bindClick('btnHealthLive', async () => { const r = await call('/health/live'); out('outMisc', r); });
  bindClick('btnHealthReady', async () => { const r = await call('/health/ready'); out('outMisc', r); });
  bindClick('btnClientToken', async () => {
  const payload = { clientId: v('ccClientId'), clientSecret: v('ccSecret'), scope: v('ccScope') };
    const r = await call('/api/v1/token/client', { method:'POST', body: JSON.stringify(payload) });
    out('outClientToken', r);
  });

  // Admin
  bindClick('btnListSessions', async () => {
  const id = v('adminUserId');
    const r = await call(`/api/v1/admin/users/${id}/sessions`, { headers: { ...auth() } });
    out('outAdmin', r);
  });
  bindClick('btnRevokeSession', async () => {
  const id = v('adminUserId'); const sid = v('adminSessId');
    const r = await call(`/api/v1/admin/users/${id}/sessions/${sid}/revoke`, { method:'POST', headers: { ...auth() } });
    out('outAdmin', r);
  });
  bindClick('btnBumpVersion', async () => {
  const id = v('adminUserId');
    const r = await call(`/api/v1/admin/users/${id}/bump-token-version`, { method:'POST', headers: { ...auth() } });
    out('outAdmin', r);
  });
  bindClick('btnLock', async () => {
  const id = v('adminUserId');
    const r = await call(`/api/v1/admin/users/${id}/lock`, { method:'POST', headers: { ...auth() } });
    out('outAdmin', r);
  });
  bindClick('btnUnlock', async () => {
  const id = v('adminUserId');
    const r = await call(`/api/v1/admin/users/${id}/unlock`, { method:'POST', headers: { ...auth() } });
    out('outAdmin', r);
  });
  bindClick('btnKeysList', async () => {
    const r = await call('/api/v1/admin/keys', { headers: { ...auth() } });
    out('outAdmin', r);
  });
  bindClick('btnKeysRotate', async () => {
    const r = await call('/api/v1/admin/keys/rotate', { method:'POST', headers: { ...auth() } });
    out('outAdmin', r);
  });
  bindClick('btnCreateClient', async () => {
  const name = v('clientName'); const scopes = v('clientScopes').trim().split(/\s+/).filter(Boolean);
    const r = await call('/api/v1/admin/client-apps', { method:'POST', headers: { ...auth() }, body: JSON.stringify({ name, scopes }) });
    out('outAdmin', r);
  });
  bindClick('btnTestEmail', async () => {
  const payload = { to: v('testTo'), subject: v('testSubject'), body: v('testBody') };
    const r = await call('/api/v1/admin/test-email', { method:'POST', headers: { ...auth() }, body: JSON.stringify(payload) });
    out('outAdmin', r);
  });
})();
