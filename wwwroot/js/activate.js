document.addEventListener('DOMContentLoaded', () => {
  const activateForm = document.getElementById('activate-form');
  const view = document.getElementById('activate-view');
  const success = document.getElementById('activate-success');
  const alertPlaceholder = document.getElementById('alert-placeholder'); 


  const params = new URLSearchParams(window.location.search);
  const token = params.get('token');
  const email = params.get('email');
  if (!token || !email) {
    showAlert('Invalid or expired activation link.');
  }

  activateForm.addEventListener('submit', async e => {
    e.preventDefault();
    alertPlaceholder.innerHTML = '';

    if (!token || !email) {
      showAlert('Invalid or expired activation link.');
      return;
    }

    const fullName = document.getElementById('act-fullname').value.trim();
    const passwordInput = document.getElementById('act-password');
    const password = passwordInput.value;
    const terms = document.getElementById('act-terms').checked;

    // Client-side validation
    const fullNameInput = document.getElementById('act-fullname');
    setValidation(fullNameInput, null);
    setValidation(passwordInput, null);
    let isValid = true;

    if (!fullName) {
        setValidation(fullNameInput, 'Full name is required.');
        isValid = false;
    }
    if (password.length < 12) {
        setValidation(passwordInput, 'Password must be at least 12 characters long.');
        isValid = false;
    }
    if (!terms) {
        showAlert('Please accept the terms and conditions.');
        isValid = false;
    }
    if (!isValid) return;

    const submitBtn = activateForm.querySelector('button[type="submit"]');
    const originalBtnText = submitBtn.textContent;
    submitBtn.disabled = true;
    submitBtn.textContent = 'Activating...';

    try {
      const r = await apiFetch('/api/v1/authenticate/activate', { method: 'POST', body: { email, token, password, fullName } }, false);
      if (!r.ok) {
        const d = await r.json().catch(() => ({}));
        throw new Error(d.error || d.message || 'Activation failed.');
      }
      view.classList.add('d-none');
      success.classList.remove('d-none');
    } catch (err) {
      showAlert(err.message);
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = originalBtnText;
    }
});
