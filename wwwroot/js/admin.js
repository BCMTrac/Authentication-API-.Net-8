document.addEventListener('DOMContentLoaded', () => {
  const API = {
    base: '/api/v1',
    admin: '/api/v1/admin',
    auth: '/api/v1/authenticate'
  };

  // UI refs
  const alertPlaceholder = document.getElementById('alert-placeholder');
  const notAdminView = document.getElementById('not-admin-view');
  const adminView = document.getElementById('admin-view');

  const searchInput = document.getElementById('search-input');
  const searchBtn = document.getElementById('search-btn');
  const results = document.getElementById('results');

  const userDetails = document.getElementById('user-details');
  const userActions = document.getElementById('user-actions');
  const rolesList = document.getElementById('roles-list');
  const roleInput = document.getElementById('role-input');
  const roleAddBtn = document.getElementById('role-add-btn');
  const tempPasswordInput = document.getElementById('temp-password');
  const tempPasswordBtn = document.getElementById('temp-password-btn');

  const btnUnlock = document.getElementById('btn-unlock');
  const btnLock = document.getElementById('btn-lock');
  const btnConfirmEmail = document.getElementById('btn-confirm-email');
  const btnResendConfirm = document.getElementById('btn-resend-confirm');
  const btnDisableMfa = document.getElementById('btn-disable-mfa');
  const btnBumpToken = document.getElementById('btn-bump-token');
  const btnSendReset = document.getElementById('btn-send-reset');

  const sessionsBody = document.getElementById('sessions-body');
  const sessionsRevokeAllBtn = document.getElementById('sessions-revoke-all');

  let auth = { token: null, refresh: null };
  let selectedUserId = null;

  // --- Helpers ---
  function loadTokens() {
    auth.token = localStorage.getItem('auth_token');
    auth.refresh = localStorage.getItem('refresh_token');
  }
  function saveTokens(token, refresh) {
    auth.token = token; auth.refresh = refresh;
    localStorage.setItem('auth_token', token);
    localStorage.setItem('refresh_token', refresh);
  }
  function showAlert(message, type = 'danger') {
    const wrapper = document.createElement('div');
    wrapper.innerHTML = [
      `<div class="alert alert-${type} alert-dismissible" role="alert">`,
      `  <div>${message}</div>`,
      '  <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>',
      '</div>'
    ].join('');
    alertPlaceholder.innerHTML = '';
    alertPlaceholder.append(wrapper);
  }

  async function apiFetch(url, options = {}) {
    const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
    if (auth.token) headers['Authorization'] = `Bearer ${auth.token}`;
    const res = await fetch(url, { ...options, headers, body: options.body ? JSON.stringify(options.body) : null });
    if (res.status === 401 && auth.refresh) {
      try {
        const rr = await fetch(`${API.auth}/refresh`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refreshToken: auth.refresh })
        });
        if (!rr.ok) throw new Error('refresh failed');
        const json = await rr.json();
        saveTokens(json.token, json.refreshToken);
        const retryHeaders = { 'Content-Type': 'application/json', ...(options.headers || {}), 'Authorization': `Bearer ${json.token}` };
        return await fetch(url, { ...options, headers: retryHeaders, body: options.body ? JSON.stringify(options.body) : null });
      } catch {
        localStorage.removeItem('auth_token');
        localStorage.removeItem('refresh_token');
        showAlert('Session expired. Go to Sign In.', 'warning');
        return res;
      }
    }
    return res;
  }

  async function ensureAdmin() {
    loadTokens();
    if (!auth.token) { notAdminView.classList.remove('d-none'); return false; }
    try {
      const me = await apiFetch(`${API.base}/users/me`);
      if (!me.ok) { notAdminView.classList.remove('d-none'); return false; }
      const data = await me.json();
      const roles = (data.roles || []).map(r => r.toLowerCase());
      if (!roles.includes('admin')) { notAdminView.classList.remove('d-none'); return false; }
      adminView.classList.remove('d-none');
      return true;
    } catch {
      notAdminView.classList.remove('d-none');
      return false;
    }
  }

  function renderResults(items) {
    results.innerHTML = '';
    if (!items.length) {
      const li = document.createElement('li');
      li.className = 'list-group-item';
      li.textContent = 'No users found';
      results.append(li);
      return;
    }
    for (const u of items) {
      const li = document.createElement('li');
      li.className = 'list-group-item d-flex justify-content-between align-items-center user-result';
      li.innerHTML = `<div>
        <div><strong>${u.userName}</strong> <span class="muted">(${u.email ?? 'no-email'})</span></div>
        <div class="small muted">${u.emailConfirmed ? 'Email confirmed' : 'Email unconfirmed'} • ${u.mfaEnabled ? 'MFA' : 'No MFA'} ${u.lockoutEnd ? '• Locked' : ''}</div>
      </div>
      <i class="fa fa-chevron-right muted"></i>`;
      li.addEventListener('click', () => selectUser(u.id));
      results.append(li);
    }
  }

  function renderRoles(roles) {
    rolesList.innerHTML = '';
    for (const r of roles) {
      const span = document.createElement('span');
      span.className = 'badge bg-secondary role-badge';
      span.textContent = r;
      span.style.cursor = 'pointer';
      span.title = 'Click to remove';
      span.addEventListener('click', async () => {
        if (!selectedUserId) return;
        const res = await apiFetch(`${API.admin}/users/${selectedUserId}/roles/remove`, { method: 'POST', body: { role: r } });
        if (!res.ok) return showAlert('Failed to remove role');
        await refreshSelectedUser();
      });
      rolesList.append(span);
    }
  }

  async function refreshSelectedUser() { if (selectedUserId) await selectUser(selectedUserId, true); }

  async function selectUser(id, keepRight = false) {
    selectedUserId = id;
    try {
      const res = await apiFetch(`${API.admin}/users/${id}`);
      if (!res.ok) throw new Error('Failed to load user');
      const u = await res.json();
      userDetails.innerHTML = `
        <div class="d-flex justify-content-between align-items-start">
          <div>
            <div class="h5 mb-1">${u.userName}</div>
            <div class="small"><i class="fa fa-envelope me-1"></i>${u.email ?? 'no-email'} • ${u.emailConfirmed ? 'Email confirmed' : 'Email unconfirmed'}</div>
            <div class="small">${u.mfaEnabled ? 'MFA Enabled' : 'MFA Disabled'} • ${u.lockoutEnd ? 'Locked' : 'Unlocked'}</div>
          </div>
          <span class="badge bg-primary role-badge">ID: ${u.id}</span>
        </div>`;
      userActions.classList.remove('d-none');
      renderRoles(u.roles || []);

      // Load sessions
      const sres = await apiFetch(`${API.admin}/users/${id}/sessions`);
      const sessions = sres.ok ? await sres.json() : [];
      sessionsBody.innerHTML = '';
      for (const s of sessions) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td class="id-col">${s.id}</td>
          <td>${formatDate(s.createdUtc)}</td>
          <td>${formatDate(s.lastSeenUtc)}</td>
          <td>${s.revokedAtUtc ? formatDate(s.revokedAtUtc) : ''}</td>
          <td>${s.ip ?? ''}</td>
          <td class="ua-col" title="${s.userAgent ?? ''}">${s.userAgent ?? ''}</td>
          <td class="text-end"><button class="btn btn-sm btn-outline-danger">Revoke</button></td>`;
        tr.querySelector('button').addEventListener('click', async () => {
          const rr = await apiFetch(`${API.admin}/users/${id}/sessions/${s.id}/revoke`, { method: 'POST' });
          if (!rr.ok) return showAlert('Failed to revoke session');
          await refreshSelectedUser();
        });
        sessionsBody.append(tr);
      }
    } catch (e) {
      showAlert(e.message || 'Failed to load user');
    }
  }

  function formatDate(dt) { if (!dt) return ''; try { return new Date(dt).toLocaleString(); } catch { return dt; } }

  // --- Event wiring ---
  searchBtn.addEventListener('click', async () => {
    try {
      const q = encodeURIComponent((searchInput.value || '').trim());
      const res = await apiFetch(`${API.admin}/users/search?q=${q}`);
      if (!res.ok) throw new Error('Search failed');
      renderResults(await res.json());
    } catch (e) { showAlert(e.message || 'Search failed'); }
  });
  searchInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') searchBtn.click(); });

  roleAddBtn.addEventListener('click', async () => {
    if (!selectedUserId) return;
    const role = (roleInput.value || '').trim();
    if (!role) return;
    const res = await apiFetch(`${API.admin}/users/${selectedUserId}/roles/add`, { method: 'POST', body: { role } });
    if (!res.ok) return showAlert('Failed to add role');
    roleInput.value = '';
    await refreshSelectedUser();
  });

  tempPasswordBtn.addEventListener('click', async () => {
    if (!selectedUserId) return;
    const pw = (tempPasswordInput.value || '').trim();
    if (!pw) return showAlert('Enter a temporary password', 'warning');
    const res = await apiFetch(`${API.admin}/users/${selectedUserId}/password/set-temporary`, { method: 'POST', body: { newPassword: pw } });
    if (!res.ok) return showAlert('Failed to set temporary password');
    tempPasswordInput.value = '';
    showAlert('Temporary password set. User sessions invalidated.', 'success');
  });

  btnUnlock.addEventListener('click', async () => { if (!selectedUserId) return; const r = await apiFetch(`${API.admin}/users/${selectedUserId}/unlock`, { method: 'POST' }); if (!r.ok) return showAlert('Failed to unlock'); await refreshSelectedUser(); });
  btnLock.addEventListener('click', async () => { if (!selectedUserId) return; const r = await apiFetch(`${API.admin}/users/${selectedUserId}/lock`, { method: 'POST' }); if (!r.ok) return showAlert('Failed to lock'); await refreshSelectedUser(); });
  btnConfirmEmail.addEventListener('click', async () => { if (!selectedUserId) return; const r = await apiFetch(`${API.admin}/users/${selectedUserId}/email/confirm`, { method: 'POST' }); if (!r.ok) return showAlert('Failed to confirm email'); await refreshSelectedUser(); });
  btnResendConfirm.addEventListener('click', async () => { if (!selectedUserId) return; const r = await apiFetch(`${API.admin}/users/${selectedUserId}/email/resend-confirm`, { method: 'POST' }); if (!r.ok) return showAlert('Failed to resend'); showAlert('Confirmation email sent.', 'success'); });
  btnDisableMfa.addEventListener('click', async () => { if (!selectedUserId) return; if (!confirm('Disable MFA for this user?')) return; const r = await apiFetch(`${API.admin}/users/${selectedUserId}/mfa/disable`, { method: 'POST' }); if (!r.ok) return showAlert('Failed to disable MFA'); await refreshSelectedUser(); });
  btnBumpToken.addEventListener('click', async () => { if (!selectedUserId) return; const r = await apiFetch(`${API.admin}/users/${selectedUserId}/bump-token-version`, { method: 'POST' }); if (!r.ok) return showAlert('Failed to bump token'); showAlert('Token version bumped. Active access tokens invalidated.', 'success'); });
  btnSendReset.addEventListener('click', async () => { if (!selectedUserId) return; const r = await apiFetch(`${API.admin}/users/${selectedUserId}/password/reset-email`, { method: 'POST' }); if (!r.ok) return showAlert('Failed to send reset email'); showAlert('Password reset email sent.', 'success'); });

  sessionsRevokeAllBtn.addEventListener('click', async () => {
    if (!selectedUserId) return; if (!confirm('Revoke all sessions for this user?')) return;
    const r = await apiFetch(`${API.admin}/users/${selectedUserId}/sessions/revoke-all`, { method: 'POST' });
    if (!r.ok) return showAlert('Failed to revoke sessions');
    await refreshSelectedUser();
  });

  // init
  (async function init() { if (await ensureAdmin()) { searchInput.focus(); } })();
});
