(() => {
  const $ = (id) => document.getElementById(id);
  // Tabs
  document.querySelectorAll('nav.tabs button').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('nav.tabs button').forEach(b=>b.classList.remove('active'));
      document.querySelectorAll('section.tab').forEach(s=>s.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(btn.dataset.tab).classList.add('active');
    });
  });
  let base = localStorage.getItem('authapi.baseUrl') || (location.origin);
  $('#baseUrl').value = base;
  $('#saveCfg').onclick = () => { base = $('#baseUrl').value.trim(); localStorage.setItem('authapi.baseUrl', base); $('#cfgMsg').textContent = 'saved'; setTimeout(()=>$('#cfgMsg').textContent='',1200); };

  let accessToken = null, refreshToken = null;
  const auth = () => accessToken ? { 'Authorization': 'Bearer ' + accessToken } : {};
  const out = (el, data) => $(el).textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);

  async function call(path, opts={}) {
    const url = base.replace(/\/$/, '') + path;
    const res = await fetch(url, { ...(opts||{}), headers: { 'Content-Type':'application/json', ...(opts.headers||{}) } });
    const text = await res.text();
    try { return { status: res.status, json: JSON.parse(text) } } catch { return { status: res.status, text } }
  }

  // Register
  $('#btnRegister').onclick = async () => {
    const payload = { username: $('#regUser').value, email: $('#regEmail').value, password: $('#regPass').value };
    const r = await call('/api/v1/authenticate/register', { method:'POST', body: JSON.stringify(payload) });
    out('outRegister', r);
  };

  // Login
  $('#btnLogin').onclick = async () => {
    const payload = { username: $('#loginUser').value, password: $('#loginPass').value, mfaCode: $('#loginMfa').value };
    const r = await call('/api/v1/authenticate/login', { method:'POST', body: JSON.stringify(payload) });
    out('outLogin', r);
    if (r.json && r.json.token) { accessToken = r.json.token; refreshToken = r.json.refreshToken; }
  };

  // Refresh
  $('#btnRefresh').onclick = async () => {
    const r = await call('/api/v1/authenticate/refresh', { method:'POST', body: JSON.stringify({ refreshToken }) });
    out('outToken', r);
    if (r.json && r.json.token) { accessToken = r.json.token; refreshToken = r.json.refreshToken; }
  };
  // Logout
  $('#btnLogout').onclick = async () => {
    const r = await call('/api/v1/authenticate/logout', { method:'POST', headers: { ...auth() }, body: JSON.stringify({ refreshToken }) });
    out('outToken', r);
  };
  // Logout All
  $('#btnLogoutAll').onclick = async () => {
    const r = await call('/api/v1/authenticate/logout-all', { method:'POST', headers: { ...auth() } });
    out('outToken', r);
  };
  $('#btnCopyToken').onclick = async () => { if (accessToken) { await navigator.clipboard.writeText(accessToken); out('outToken', 'token copied'); } else out('outToken', 'no token'); };
  $('#btnDecodeToken').onclick = () => {
    if (!accessToken) { out('outTokenDecoded', 'no token'); return; }
    const parts = accessToken.split('.');
    if (parts.length < 2) { out('outTokenDecoded', 'invalid token'); return; }
    const payload = JSON.parse(atob(parts[1].replace(/-/g,'+').replace(/_/g,'/')));
    out('outTokenDecoded', payload);
  };
  $('#btnChangePassword').onclick = async () => {
    const r = await call('/api/v1/authenticate/change-password', { method:'POST', headers: { ...auth() }, body: JSON.stringify({ currentPassword: $('#cpCurrent').value, newPassword: $('#cpNew').value }) });
    out('outChangePassword', r);
  };
  // Me
  $('#btnMe').onclick = async () => {
    const r = await call('/api/v1/users/me', { headers: { ...auth() } });
    out('outToken', r);
    if (r.json && r.json.Id) {
      $('#adminUserId').value = r.json.Id;
    }
  };

  // Email flows
  $('#btnReqConfirm').onclick = async () => {
    const r = await call('/api/v1/authenticate/request-email-confirm', { method:'POST', body: JSON.stringify({ email: $('#emailAddr').value }) });
    out('outEmail', r);
  };
  $('#btnConfirmEmail').onclick = async () => {
    const r = await call('/api/v1/authenticate/confirm-email', { method:'POST', body: JSON.stringify({ email: $('#emailAddr').value, token: $('#emailToken').value }) });
    out('outEmail', r);
  };
  $('#btnReqReset').onclick = async () => {
    const r = await call('/api/v1/authenticate/request-password-reset', { method:'POST', body: JSON.stringify({ email: $('#resetEmail').value }) });
    out('outEmail', r);
  };
  $('#btnDoReset').onclick = async () => {
    const r = await call('/api/v1/authenticate/confirm-password-reset', { method:'POST', body: JSON.stringify({ email: $('#resetEmail').value, token: $('#resetToken').value, newPassword: $('#resetNew').value }) });
    out('outEmail', r);
  };

  // Change email
  $('#btnChgEmailStart').onclick = async () => {
    const r = await call('/api/v1/authenticate/change-email/start', { method:'POST', headers: { ...auth() }, body: JSON.stringify({ newEmail: $('#chgNewEmail').value }) });
    out('outChangeEmail', r);
  };
  $('#btnChgEmailConfirm').onclick = async () => {
    const r = await call('/api/v1/authenticate/change-email/confirm', { method:'POST', headers: { ...auth() }, body: JSON.stringify({ newEmail: $('#chgNewEmail').value, token: $('#chgToken').value }) });
    out('outChangeEmail', r);
  };

  // Revoke specific refresh
  $('#btnRevoke').onclick = async () => {
    const token = $('#revokeToken').value || refreshToken;
    const r = await call('/api/v1/authenticate/revoke-refresh', { method:'POST', body: JSON.stringify({ refreshToken: token }) });
    out('outRevoke', r);
  };

  // MFA
  $('#btnMfaStart').onclick = async () => { const r = await call('/api/v1/authenticate/mfa/enroll/start', { method:'POST', headers: { ...auth() } }); out('outMfa', r); };
  $('#btnMfaQr').onclick = async () => {
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
      cont.textContent = ''; cont.appendChild(pre);
    } else { out('outMfa', { status: res.status, text: await res.text() }); }
  };
  $('#btnMfaConfirm').onclick = async () => { const r = await call('/api/v1/authenticate/mfa/enroll/confirm', { method:'POST', headers: { ...auth() }, body: JSON.stringify({ code: $('#mfaCode').value }) }); out('outMfa', r); };
  $('#btnMfaDisable').onclick = async () => { const r = await call('/api/v1/authenticate/mfa/disable', { method:'POST', headers: { ...auth() } }); out('outMfa', r); };
  $('#btnMfaRegen').onclick = async () => { const r = await call('/api/v1/authenticate/mfa/recovery/regenerate', { method:'POST', headers: { ...auth() } }); out('outMfa', r); };

  // Misc
  $('#btnJwks').onclick = async () => { const r = await call('/.well-known/jwks.json'); out('outMisc', r); };
  $('#btnHealthLive').onclick = async () => { const r = await call('/health/live'); out('outMisc', r); };
  $('#btnHealthReady').onclick = async () => { const r = await call('/health/ready'); out('outMisc', r); };
  $('#btnClientToken').onclick = async () => {
    const payload = { clientId: $('#ccClientId').value, clientSecret: $('#ccSecret').value, scope: $('#ccScope').value };
    const r = await call('/api/v1/token/client', { method:'POST', body: JSON.stringify(payload) });
    out('outClientToken', r);
  };

  // Admin
  $('#btnListSessions').onclick = async () => {
    const id = $('#adminUserId').value;
    const r = await call(`/api/v1/admin/users/${id}/sessions`, { headers: { ...auth() } });
    out('outAdmin', r);
  };
  $('#btnRevokeSession').onclick = async () => {
    const id = $('#adminUserId').value; const sid = $('#adminSessId').value;
    const r = await call(`/api/v1/admin/users/${id}/sessions/${sid}/revoke`, { method:'POST', headers: { ...auth() } });
    out('outAdmin', r);
  };
  $('#btnBumpVersion').onclick = async () => {
    const id = $('#adminUserId').value;
    const r = await call(`/api/v1/admin/users/${id}/bump-token-version`, { method:'POST', headers: { ...auth() } });
    out('outAdmin', r);
  };
  $('#btnLock').onclick = async () => {
    const id = $('#adminUserId').value;
    const r = await call(`/api/v1/admin/users/${id}/lock`, { method:'POST', headers: { ...auth() } });
    out('outAdmin', r);
  };
  $('#btnUnlock').onclick = async () => {
    const id = $('#adminUserId').value;
    const r = await call(`/api/v1/admin/users/${id}/unlock`, { method:'POST', headers: { ...auth() } });
    out('outAdmin', r);
  };
  $('#btnKeysList').onclick = async () => {
    const r = await call('/api/v1/admin/keys', { headers: { ...auth() } });
    out('outAdmin', r);
  };
  $('#btnKeysRotate').onclick = async () => {
    const r = await call('/api/v1/admin/keys/rotate', { method:'POST', headers: { ...auth() } });
    out('outAdmin', r);
  };
  $('#btnCreateClient').onclick = async () => {
    const name = $('#clientName').value; const scopes = $('#clientScopes').value.trim().split(/\s+/).filter(Boolean);
    const r = await call('/api/v1/admin/client-apps', { method:'POST', headers: { ...auth() }, body: JSON.stringify({ name, scopes }) });
    out('outAdmin', r);
  };
  $('#btnTestEmail').onclick = async () => {
    const payload = { to: $('#testTo').value, subject: $('#testSubject').value, body: $('#testBody').value };
    const r = await call('/api/v1/admin/test-email', { method:'POST', headers: { ...auth() }, body: JSON.stringify(payload) });
    out('outAdmin', r);
  };
})();
