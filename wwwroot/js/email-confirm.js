document.addEventListener('DOMContentLoaded', () => {
  const API_BASE_URL = '/api/v1/authenticate';
  const $ = (id) => document.getElementById(id);
  const email = $('email');
  const token = $('token');
  const confirmAccountBtn = $('confirm-account-btn');
  const confirmChangeBtn = $('confirm-change-btn');
  const confirmView = $('confirm-view');
  const successView = $('success-view');
  const alertHost = $('alert-placeholder');

  function showAlert(message, type = 'danger') {
    alertHost.innerHTML = `
      <div class="alert alert-${type}" role="alert">
        <div>${message}</div>
      </div>`;
  }

  // Autofill from query string if present
  try {
    const u = new URL(window.location.href);
    const qEmail = u.searchParams.get('email');
    const qToken = u.searchParams.get('token');
    if (qEmail) email.value = qEmail;
    if (qToken) token.value = qToken;
  } catch {}

  function setLoading(btn, on) {
    const spinner = btn.querySelector('.spinner-border');
    const label = btn.querySelector('.btn-label');
    if (label && !label.dataset.default) label.dataset.default = label.textContent || '';
    btn.disabled = !!on;
    if (spinner) spinner.classList.toggle('d-none', !on);
    if (label) label.textContent = on ? 'Working…' : (label.dataset.default || 'Submit');
  }

  function validate() {
    let ok = true;
    const vEmail = email.value.trim();
    const vToken = token.value.trim();
    if (!vEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(vEmail)) { email.classList.add('is-invalid'); ok = false; } else { email.classList.remove('is-invalid'); }
    if (!vToken) { token.classList.add('is-invalid'); ok = false; } else { token.classList.remove('is-invalid'); }
    return ok;
  }

  async function postJson(url, body) {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(body)
    });
    return res;
  }

  async function handle(kind) {
    if (!validate()) return;
    const btn = kind === 'account' ? confirmAccountBtn : confirmChangeBtn;
    setLoading(btn, true);
    showAlert('Submitting…', 'info');
    try {
      const payload = { email: email.value.trim(), token: token.value.trim() };
      let endpoint = `${API_BASE_URL}/confirm-email`;
      if (kind === 'change') {
        endpoint = `${API_BASE_URL}/change-email/confirm`;
      }
      const body = kind === 'change' ? { newEmail: payload.email, token: payload.token } : payload;
      const res = await postJson(endpoint, body);
      if (!res.ok) {
        let msg = 'Confirmation failed. Check your token and try again.';
        try { const data = await res.json(); msg = data.message || data.error || msg; } catch {}
        throw new Error(msg);
      }
      confirmView.classList.add('d-none');
      successView.classList.remove('d-none');
      alertHost.innerHTML = '';
    } catch (e) {
      showAlert(e.message || 'Something went wrong');
    } finally {
      setLoading(btn, false);
    }
  }

  confirmAccountBtn.addEventListener('click', () => handle('account'));
  confirmChangeBtn.addEventListener('click', () => handle('change'));

  // Enter key triggers primary action
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); confirmAccountBtn.click(); }
  });
});

