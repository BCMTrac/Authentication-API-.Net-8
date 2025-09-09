(() => {
  const $ = (id) => document.getElementById(id);
  const bindClick = (id, handler) => { const el = $(id); if (el) el.onclick = handler; };
  const v = (id) => (document.getElementById(id)?.value ?? '').toString();
  const vt = (id) => v(id).trim();
  const isEmail = (s) => /.+@.+\..+/.test(s);
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

  let accessToken = null, refreshToken = null, currentOtpauthUrl = null;
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
  const chgStart = document.getElementById('btnChgEmailStart');
  if (chgStart) chgStart.disabled = !accessToken;
  const chgConfirm = document.getElementById('btnChgEmailConfirm');
  if (chgConfirm) chgConfirm.disabled = !accessToken;
  const mfaBtns = ['btnMfaStart','btnMfaQr','btnMfaConfirm','btnMfaDisable','btnMfaRegen'];
  mfaBtns.forEach(id => { const el = document.getElementById(id); if (el) el.disabled = !accessToken; });
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
    const username = vt('regUser');
    const email = vt('regEmail');
    const pwd = v('regPass');
    if (!username || !email || !pwd) { out('outRegister', { ok:false, message:'Please fill in username, email and password.' }); return; }
    if (!isEmail(email)) { out('outRegister', { ok:false, message:'Enter a valid email address.' }); return; }
    if (!meetsPwd(pwd)) { out('outRegister', { ok:false, message:'Password must be \u226512 and include uppercase, lowercase, digit, and symbol.' }); return; }
    const payload = { username, email, fullName: v('regFullName'), phone: v('regPhone'), password: pwd, termsAccepted: document.getElementById('regTerms')?.checked === true, marketingOptIn: document.getElementById('regMarketing')?.checked === true };
    const r = await call('/api/v1/authenticate/register', { method:'POST', body: JSON.stringify(payload) });
    if (r.ok) {
      out('outRegister', 'If that email exists, we\'ve sent a confirmation link.');
    } else {
      out('outRegister', r);
    }
  });

  // Login
  bindClick('btnLogin', async () => {
  const identifier = vt('loginUser');
  const password = v('loginPass');
  if (!identifier || !password) { out('outLogin', { ok:false, message:'Please fill in identifier and password.' }); return; }
  const payload = { identifier, password, mfaCode: vt('loginMfa') };
    const r = await call('/api/v1/authenticate/login', { method:'POST', headers: { 'X-Login-Id': identifier }, body: JSON.stringify(payload) });
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
    const newPwd = v('cpNew');
    if (!meetsPwd(newPwd)) { out('outChangePassword', { ok:false, message:'New password must be \u226512 and include uppercase, lowercase, digit, and symbol.' }); return; }
    const r = await call('/api/v1/authenticate/change-password', { method:'POST', headers: { ...auth() }, body: JSON.stringify({ currentPassword: v('cpCurrent'), newPassword: newPwd }) });
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
  const em = vt('emailAddr'); if (!em){ out('outEmail','Please enter email'); return; }
  const r = await call('/api/v1/authenticate/request-email-confirm', { method:'POST', body: JSON.stringify({ email: em }) });
  out('outEmail', r);
  });
  bindClick('btnConfirmEmail', async () => {
  const cem = vt('emailAddr'); const ctk = vt('emailToken'); if (!cem || !ctk){ out('outEmail','Enter email and token'); return; }
  const r = await call('/api/v1/authenticate/confirm-email', { method:'POST', body: JSON.stringify({ email: cem, token: ctk }) });
    out('outEmail', r);
  });
  
  bindClick('btnReqReset', async () => {
  const rem = vt('resetEmail'); if (!rem){ out('outEmail','Enter reset email'); return; }
  const r = await call('/api/v1/authenticate/request-password-reset', { method:'POST', body: JSON.stringify({ email: rem }) });
  out('outEmail', r);
  });
  bindClick('btnDoReset', async () => {
  const rem2 = vt('resetEmail'); const rtk = vt('resetToken'); const np = v('resetNew');
  if (!rem2 || !rtk){ out('outEmail','Enter email and reset token'); return; }
  if (!meetsPwd(np)) { out('outEmail', { ok:false, message:'New password must be \u226512 and include uppercase, lowercase, digit, and symbol.' }); return; }
  const r = await call('/api/v1/authenticate/confirm-password-reset', { method:'POST', body: JSON.stringify({ email: rem2, token: rtk, newPassword: np }) });
    out('outEmail', r);
  });
  

  // Change email
  bindClick('btnChgEmailStart', async () => {
  if (!accessToken) { out('outChangeEmail', 'login first'); return; }
  const ne = vt('chgNewEmail'); if (!ne){ out('outChangeEmail','Enter a new email'); return; }
  const r = await call('/api/v1/authenticate/change-email/start', { method:'POST', headers: { ...auth() }, body: JSON.stringify({ newEmail: ne }) });
  out('outChangeEmail', r);
  });
  bindClick('btnChgEmailConfirm', async () => {
  if (!accessToken) { out('outChangeEmail', 'login first'); return; }
  const ne2 = vt('chgNewEmail'); const tok = vt('chgToken'); if (!ne2 || !tok){ out('outChangeEmail','Enter new email and token'); return; }
  const r = await call('/api/v1/authenticate/change-email/confirm', { method:'POST', headers: { ...auth() }, body: JSON.stringify({ newEmail: ne2, token: tok }) });
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
  bindClick('btnMfaStart', async () => {
    const r = await call('/api/v1/authenticate/mfa/enroll/start', { method:'POST', headers: { ...auth() } });
    out('outMfa', r);
    if (r.json && r.json.otpauthUrl) { currentOtpauthUrl = r.json.otpauthUrl; }
  });
  bindClick('btnMfaQr', async () => {
    if (!accessToken) { out('outMfa', 'login first'); return; }
    if (!currentOtpauthUrl) { out('outMfa', 'Start enrollment first to get otpauthUrl'); return; }
    const url = base.replace(/\/$/, '') + '/api/v1/mfa/qr?otpauthUrl=' + encodeURIComponent(currentOtpauthUrl);
    const res = await fetch(url, { headers: { ...auth() } });
    if (res.ok) {
      const buf = await res.arrayBuffer();
      const bytes = new Uint8Array(buf);
      let bin = '';
      for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      const b64 = btoa(bin);
      const img = document.createElement('img');
      img.className = 'qr-img';
      img.src = 'data:image/png;base64,' + b64;
      const wrap = document.createElement('div');
      wrap.className = 'qr-wrap';
      wrap.appendChild(img);
      const cont = document.getElementById('outMfa');
      if (cont) { cont.textContent = ''; cont.appendChild(wrap); }
    } else { out('outMfa', { status: res.status, text: await res.text() }); }
  });
  bindClick('btnMfaConfirm', async () => { const code = vt('mfaCode'); if (!/^\d{6}$/.test(code) && !code){ out('outMfa','Enter a 6-digit code or a recovery code'); return; } const r = await call('/api/v1/authenticate/mfa/enroll/confirm', { method:'POST', headers: { ...auth() }, body: JSON.stringify({ code }) }); out('outMfa', r); });
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
  // Password requirement checker + live checklist
  function meetsPwd(p){
    return typeof p === 'string' && p.length >= 12 && /[A-Z]/.test(p) && /[a-z]/.test(p) && /\d/.test(p) && /[^A-Za-z0-9]/.test(p);
  }
  function bindPwdChecklist(inputId, prefix){
    const el = document.getElementById(inputId);
    if (!el) return;
    const upd = () => {
      const val = el.value || '';
      const checks = {
        Len: val.length >= 12,
        Upper: /[A-Z]/.test(val),
        Lower: /[a-z]/.test(val),
        Digit: /\d/.test(val),
        Symbol: /[^A-Za-z0-9]/.test(val),
      };
      Object.entries(checks).forEach(([k, ok]) => {
        const li = document.getElementById(prefix + k);
        if (li) li.classList.toggle('ok', !!ok);
      });
    };
    el.addEventListener('input', upd);
    upd();
  }
  bindPwdChecklist('regPass','rp');
  bindPwdChecklist('cpNew','cp');
  bindPwdChecklist('resetNew','rs');
  bindPwdToggle();
  function bindPwdToggle(){
    document.querySelectorAll('.pwd-toggle').forEach(btn => {
      const id = btn.getAttribute('data-target');
      const input = document.getElementById(id);
      if (!input) return;
      btn.addEventListener('click', () => {
        const isPwd = input.type === 'password';
        input.type = isPwd ? 'text' : 'password';
        btn.textContent = isPwd ? 'Hide' : 'Show';
        btn.setAttribute('aria-label', isPwd ? 'Hide password' : 'Show password');
      });
    });
  }
})();
