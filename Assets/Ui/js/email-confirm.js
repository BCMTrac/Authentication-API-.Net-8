document.addEventListener('DOMContentLoaded', () => {
  const API_BASE_URL = '/api/v1/authenticate';

  const emailInput = document.getElementById('email');
  const tokenInput = document.getElementById('token');
  const confirmAccountBtn = document.getElementById('confirm-account-btn');
  const confirmChangeBtn = document.getElementById('confirm-change-btn');
  const confirmView = document.getElementById('confirm-view');
  const successView = document.getElementById('success-view');
  const alertPlaceholder = document.getElementById('alert-placeholder');

  function showAlert(message, type = 'danger') {
    const wrapper = document.createElement('div');
    wrapper.innerHTML = [
      `<div class="alert alert-${type} alert-dismissible" role="alert">`,
      `   <div>${message}</div>`,
      '   <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>',
      '</div>'
    ].join('');
    alertPlaceholder.innerHTML = '';
    alertPlaceholder.append(wrapper);
  }

  const params = new URLSearchParams(window.location.search);
  const qsEmail = params.get('email');
  const qsToken = params.get('token');
  if (qsEmail) emailInput.value = qsEmail;
  if (qsToken) tokenInput.value = qsToken;

  async function postJson(url, body) {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    return res;
  }

  async function handleConfirm(endpoint, body) {
    try {
      const res = await postJson(`${API_BASE_URL}/${endpoint}`, body);
      if (!res.ok) {
        let msg = 'Confirmation failed.';
        try {
          const data = await res.json();
          msg = data.message || (data.errors ? data.errors.join(', ') : msg);
        } catch {}
        throw new Error(msg);
      }
      confirmView.classList.add('d-none');
      successView.classList.remove('d-none');
    } catch (err) {
      showAlert(err.message || 'Something went wrong');
    }
  }

  confirmAccountBtn.addEventListener('click', () => {
    const email = emailInput.value.trim();
    const token = tokenInput.value.trim();
    if (!email || !token) return showAlert('Email and token are required.');
    handleConfirm('confirm-email', { email, token });
  });

  confirmChangeBtn.addEventListener('click', () => {
    const email = emailInput.value.trim();
    const token = tokenInput.value.trim();
    if (!email || !token) return showAlert('New email and token are required.');
    handleConfirm('change-email/confirm', { newEmail: email, token });
  });
});

