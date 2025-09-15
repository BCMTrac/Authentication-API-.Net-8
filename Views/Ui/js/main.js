document.addEventListener('DOMContentLoaded', () => {
  const API_BASE_URL = '/api/v1';
  const loginView = document.getElementById('login-view');
  const registerView = document.getElementById('register-view');
  const forgotPasswordView = document.getElementById('forgot-password-view');
  const loggedInView = document.getElementById('logged-in-view');
  const views = [loginView, registerView, forgotPasswordView, loggedInView];
  const loginForm = document.getElementById('login-form');
  const registerForm = document.getElementById('register-form');
  const forgotPasswordForm = document.getElementById('forgot-password-form');
  const changePasswordForm = document.getElementById('change-password-form');
  const showRegisterLink = document.getElementById('show-register');
  const showLoginFromRegisterLink = document.getElementById('show-login-from-register');
  const showForgotPasswordLink = document.getElementById('show-forgot-password');
  const showLoginFromForgotLink = document.getElementById('show-login-from-forgot');
  const resendConfirmLink = document.getElementById('resend-confirm-link');
  const logoutButton = document.getElementById('logout-button');
  const logoutAllButton = document.getElementById('logout-all-button');
  const mfaInputContainer = document.getElementById('mfa-input-container');
  const alertPlaceholder = document.getElementById('alert-placeholder');
  const userInfo = document.getElementById('user-info');
  const mfaManagementView = document.getElementById('mfa-management-view');
  let authTokens = { token: null, refreshToken: null };

  function saveTokens(token, refreshToken) {
    authTokens.token = token;
    authTokens.refreshToken = refreshToken;
    localStorage.setItem('auth_token', token);
    if (refreshToken) localStorage.setItem('refresh_token', refreshToken);
  }
  function loadTokens() {
    authTokens.token = localStorage.getItem('auth_token');
    authTokens.refreshToken = localStorage.getItem('refresh_token');
  }
  function clearTokens() {
    authTokens.token = null;
    authTokens.refreshToken = null;
    localStorage.removeItem('auth_token');
    localStorage.removeItem('refresh_token');
  }
  function switchView(targetView) {
    views.forEach(v => v.classList.toggle('d-none', v.id !== targetView));
    clearAlert();
  }
  function showAlert(message, type = 'danger') {
    const wrapper = document.createElement('div');
    wrapper.innerHTML = [`<div class="alert alert-${type} alert-dismissible" role="alert">`,
      `   <div>${message}</div>`,
      '   <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>',
      '</div>'].join('');
    alertPlaceholder.append(wrapper);
  }
  function clearAlert() { alertPlaceholder.innerHTML = ''; }

  async function apiFetch(endpoint, options = {}) {
    const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
    if (authTokens.token) headers['Authorization'] = `Bearer ${authTokens.token}`;
    const res = await fetch(`${API_BASE_URL}${endpoint}`, { ...options, headers, body: options.body ? JSON.stringify(options.body) : null });
    if (res.status === 401) return await refreshTokenAndRetry(endpoint, options);
    return res;
  }
  async function refreshTokenAndRetry(originalEndpoint, originalOptions) {
    try {
      const body = authTokens.refreshToken ? { refreshToken: authTokens.refreshToken } : {};
      const rr = await fetch(`${API_BASE_URL}/authenticate/refresh`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      if (!rr.ok) throw new Error('Refresh token failed');
      const json = await rr.json();
      if (json.token) { authTokens.token = json.token; localStorage.setItem('auth_token', json.token); }
      if (json.refreshToken) { authTokens.refreshToken = json.refreshToken; localStorage.setItem('refresh_token', json.refreshToken); }
      originalOptions.headers = { ...(originalOptions.headers || {}), 'Authorization': `Bearer ${json.token}` };
      return await apiFetch(originalEndpoint, originalOptions);
    } catch (e) {
      handleLogout(); showAlert('Your session has expired. Please sign in again.', 'warning'); return Promise.reject('Session expired');
    }
  }

  showRegisterLink.addEventListener('click', e => { e.preventDefault(); switchView('register-view'); });
  showLoginFromRegisterLink.addEventListener('click', e => { e.preventDefault(); switchView('login-view'); });
  showForgotPasswordLink.addEventListener('click', e => { e.preventDefault(); switchView('forgot-password-view'); });
  showLoginFromForgotLink.addEventListener('click', e => { e.preventDefault(); switchView('login-view'); });
  resendConfirmLink.addEventListener('click', async e => {
    e.preventDefault(); clearAlert();
    let email = document.getElementById('login-identifier').value || '';
    if (!email.includes('@')) email = prompt('Enter your account email to resend confirmation:') || '';
    email = email.trim(); if (!email) return;
    try {
      const res = await apiFetch('/authenticate/request-email-confirm', { method: 'POST', body: { email } });
      if (!res.ok) throw new Error('Could not send confirmation email.');
      showAlert('If the email exists and is unconfirmed, a confirmation email has been sent.', 'success');
    } catch (err) { showAlert(err.message); }
  });

  loginForm.addEventListener('submit', async e => {
    e.preventDefault(); clearAlert();
    const identifier = document.getElementById('login-identifier').value;
    const password = document.getElementById('login-password').value;
    const mfaCode = document.getElementById('login-mfa').value;
    const body = { identifier, password }; if (mfaCode) body.mfaCode = mfaCode;
    try {
      const resp = await apiFetch('/authenticate/login', { method: 'POST', body });
      const data = await resp.json(); if (!resp.ok) throw new Error(data.error || data.message || 'Login failed');
      if (data.mfaRequired) { mfaInputContainer.classList.remove('d-none'); showAlert('MFA code required', 'info'); }
      else if (data.token) { saveTokens(data.token, data.refreshToken || authTokens.refreshToken); await showDashboard(); }
    } catch (err) { showAlert(err.message); }
  });

  registerForm.addEventListener('submit', async e => {
    e.preventDefault(); clearAlert();
    const body = { username: document.getElementById('register-username').value, fullName: document.getElementById('register-fullname').value, email: document.getElementById('register-email').value, password: document.getElementById('register-password').value, termsAccepted: document.getElementById('register-terms').checked };
    try {
      const resp = await apiFetch('/authenticate/register', { method: 'POST', body }); const data = await resp.json();
      if (!resp.ok) throw new Error(data.message || 'Registration failed');
      showAlert('Registration successful! Please check your email to confirm your account.', 'success'); switchView('login-view');
    } catch (err) { showAlert(err.message); }
  });

  forgotPasswordForm.addEventListener('submit', async e => {
    e.preventDefault(); clearAlert(); const email = document.getElementById('forgot-email').value;
    try {
      const resp = await apiFetch('/authenticate/request-password-reset', { method: 'POST', body: { email } }); if (!resp.ok) throw new Error('Something went wrong.');
      showAlert('If an account with that email exists, a password reset link has been sent.', 'success'); switchView('login-view');
    } catch (err) { showAlert(err.message); }
  });

  logoutButton.addEventListener('click', async e => { e.preventDefault(); await handleLogout(); });
  logoutAllButton.addEventListener('click', async e => {
    e.preventDefault(); try { const resp = await apiFetch('/authenticate/logout-all', { method: 'POST' }); if (!resp.ok) throw new Error('Could not log out all devices.'); handleLogout(); showAlert('Successfully logged out of all devices.', 'success'); } catch (err) { showAlert(err.message); }
  });

  changePasswordForm.addEventListener('submit', async e => {
    e.preventDefault(); clearAlert();
    const body = { currentPassword: document.getElementById('current-password').value, newPassword: document.getElementById('new-password').value };
    try { const resp = await apiFetch('/authenticate/change-password', { method: 'POST', body }); if (!resp.ok) { const data = await resp.json(); throw new Error(data.errors ? data.errors.join(', ') : (data.message || 'Password change failed.')); }
      showAlert('Password changed successfully.', 'success'); changePasswordForm.reset();
    } catch (err) { showAlert(err.message); }
  });

  async function showDashboard() {
    switchView('logged-in-view');
    try { const resp = await apiFetch('/users/me'); if (!resp.ok) throw new Error('Could not fetch user data.'); const user = await resp.json();
      userInfo.innerHTML = `<p><strong>Username:</strong> ${user.userName}</p><p><strong>Email:</strong> ${user.email} (${user.emailConfirmed ? 'Verified' : 'Not Verified'})</p><p><strong>MFA Enabled:</strong> ${user.mfaEnabled ? 'Yes' : 'No'}</p>`;
      renderMfaManagement(user.mfaEnabled);
    } catch (err) { showAlert(err.message, 'warning'); }
  }
  function renderMfaManagement(isEnabled) {
    if (isEnabled) {
      mfaManagementView.innerHTML = `<div class="card"><div class="card-body"><h5 class="card-title">MFA is Enabled</h5><button id="disable-mfa-btn" class="btn btn-warning">Disable MFA</button><button id="regen-recovery-btn" class="btn btn-secondary">Regenerate Recovery Codes</button></div></div>`;
      document.getElementById('disable-mfa-btn').addEventListener('click', disableMfa);
      document.getElementById('regen-recovery-btn').addEventListener('click', regenerateRecoveryCodes);
    } else {
      mfaManagementView.innerHTML = `<div class="card"><div class="card-body"><h5 class="card-title">Enable Two-Factor Authentication</h5><p>Add an extra layer of security to your account.</p><button id="enable-mfa-btn" class="btn btn-success">Enable MFA</button><div id="mfa-enroll-flow" class="d-none mt-3"></div></div></div>`;
      document.getElementById('enable-mfa-btn').addEventListener('click', startMfaEnrollment);
    }
  }
  async function startMfaEnrollment() {
    try { const resp = await apiFetch('/authenticate/mfa/enroll/start', { method: 'POST' }); if (!resp.ok) throw new Error('Could not start MFA enrollment.'); const data = await resp.json();
      const enroll = document.getElementById('mfa-enroll-flow'); enroll.classList.remove('d-none');
      enroll.innerHTML = `<p>1. Scan this QR code with your authenticator app:</p><div id="qr-code-container" class="text-center"><img src="${API_BASE_URL}/mfa/qr?otpauthUrl=${encodeURIComponent(data.otpauthUrl)}" alt="MFA QR Code"></div><p>2. Enter the code from your app to confirm:</p><form id="confirm-mfa-form"><div class="input-group mb-3"><input type="text" id="mfa-confirm-code" class="form-control" placeholder="6-digit code" required><button type="submit" class="btn btn-primary">Confirm & Enable</button></div></form>`;
      document.getElementById('confirm-mfa-form').addEventListener('submit', confirmMfaEnrollment);
    } catch (err) { showAlert(err.message); }
  }
  async function confirmMfaEnrollment(e) {
    e.preventDefault(); const code = document.getElementById('mfa-confirm-code').value;
    try { const resp = await apiFetch('/authenticate/mfa/enroll/confirm', { method: 'POST', body: { code } }); if (!resp.ok) throw new Error('Invalid MFA code.'); const data = await resp.json();
      mfaManagementView.innerHTML = `<div class="alert alert-success">MFA Enabled Successfully!</div><h5>Save these recovery codes!</h5><p>Store them somewhere safe. You can use them to access your account if you lose your device.</p><div class="recovery-codes p-3 bg-light rounded">${data.recoveryCodes.join('<br>')}</div><button id="mfa-done-btn" class="btn btn-primary mt-3">Done</button>`;
      document.getElementById('mfa-done-btn').addEventListener('click', showDashboard);
    } catch (err) { showAlert(err.message); }
  }
  async function disableMfa() { if (!confirm('Are you sure you want to disable MFA?')) return; try { const resp = await apiFetch('/authenticate/mfa/disable', { method: 'POST' }); if (!resp.ok) throw new Error('Could not disable MFA.'); showAlert('MFA has been disabled.', 'success'); showDashboard(); } catch (err) { showAlert(err.message); } }
  async function regenerateRecoveryCodes() { if (!confirm('This will invalidate your old recovery codes. Are you sure?')) return; try { const resp = await apiFetch('/authenticate/mfa/recovery/regenerate', { method: 'POST' }); if (!resp.ok) throw new Error('Could not regenerate codes.'); const data = await resp.json(); mfaManagementView.querySelector('.card-body').innerHTML = `<div class=\"alert alert-success\">New Recovery Codes Generated!</div><h5>Save these new codes!</h5><div class=\"recovery-codes p-3 bg-light rounded\">${data.recoveryCodes.join('<br>')}</div><button id=\"mfa-done-btn\" class=\"btn btn-primary mt-3\">Done</button>`; document.getElementById('mfa-done-btn').addEventListener('click', showDashboard); } catch (err) { showAlert(err.message); } }
  async function handleLogout() { try { if (authTokens.refreshToken) await apiFetch('/authenticate/logout', { method: 'POST', body: { refreshToken: authTokens.refreshToken } }); else await apiFetch('/authenticate/logout', { method: 'POST', body: {} }); } catch(_){} finally { clearTokens(); switchView('login-view'); } }
  function init() { loadTokens(); if (authTokens.token) showDashboard(); else switchView('login-view'); }
  init();
});

