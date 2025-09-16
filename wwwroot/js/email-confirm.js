document.addEventListener('DOMContentLoaded', () => {
  const API_BASE_URL = '/api/v1/authenticate';
  const emailInput = document.getElementById('email');
  const tokenInput = document.getElementById('token');
  const confirmAccountBtn = document.getElementById('confirm-account-btn');
  const confirmChangeBtn = document.getElementById('confirm-change-btn');
  const resendBtn = document.getElementById('resend-confirm-btn');
  const confirmView = document.getElementById('confirm-view');
  const successView = document.getElementById('success-view');
  const alertPlaceholder = document.getElementById('alert-placeholder'); 
 

  const params = new URLSearchParams(window.location.search);
  const qsEmail = params.get('email');
  const qsToken = params.get('token');
  if (qsEmail) emailInput.value = qsEmail;
  if (qsToken) tokenInput.value = qsToken;

  async function handleConfirm(endpoint, body, btn) {
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Confirming...';
    try {
      const res = await apiFetch(`${API_BASE_URL}/${endpoint}`, { method: 'POST', body: body }, false);
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        const errorMsg = data.message || (data.errors ? data.errors.join(', ') : 'Confirmation failed.');
        throw new Error(errorMsg);
      }
      confirmView.classList.add('d-none');
      successView.classList.remove('d-none');
    } catch (err) {
      showAlert(err.message || 'Something went wrong');
    } finally {
      btn.disabled = false;
      btn.textContent = originalText;
    }
  }

  function validateEmailAndToken(emailInput, tokenInput, emailLabel) {
    setValidation(emailInput, null);
    setValidation(tokenInput, null);
    let isValid = true;

    const email = emailInput.value.trim();
    const token = tokenInput.value.trim();

    if (!email) {
      setValidation(emailInput, `${emailLabel} is required.`);
      isValid = false;
    } else if (!isValidEmail(email)) {
      setValidation(emailInput, 'Please enter a valid email address.');
      isValid = false;
    }
    if (!token) {
      setValidation(tokenInput, 'Token is required.');
      isValid = false;
    }
    return isValid ? { email, token } : null;
  }

  confirmAccountBtn.addEventListener('click', () => {
    const validationResult = validateEmailAndToken(emailInput, tokenInput, 'Email');
    if (!validationResult) return;
    handleConfirm('confirm-email', { email: validationResult.email, token: validationResult.token }, confirmAccountBtn);
  });

  confirmChangeBtn.addEventListener('click', () => {
    const validationResult = validateEmailAndToken(emailInput, tokenInput, 'New email');
    if (!validationResult) return;
    handleConfirm('change-email/confirm', { newEmail: validationResult.email, token: validationResult.token }, confirmChangeBtn);
  });

  resendBtn.addEventListener('click', async () => {
    const email = emailInput.value.trim();
    setValidation(emailInput, null); 

    if (!email) {
      setValidation(emailInput, 'Enter your email to resend confirmation.');
      return;
    } else if (!isValidEmail(email)) {
      setValidation(emailInput, 'Please enter a valid email address.');
      return;
    }

    const originalText = resendBtn.textContent;
    resendBtn.disabled = true;
    resendBtn.textContent = 'Sending...';

    try {
      const res = await apiFetch(`${API_BASE_URL}/request-email-confirm`, { method: 'POST', body: { email } }, false); // No auth token needed
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.message || 'Could not send confirmation.');
      }
      showAlert('If this email exists, a new confirmation has been sent.', 'success');
    } catch (err) {
      showAlert(err.message || 'Something went wrong');
    } finally {
      resendBtn.disabled = false;
      resendBtn.textContent = originalText;
    }
  });
});