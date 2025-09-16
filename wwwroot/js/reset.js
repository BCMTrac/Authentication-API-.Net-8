document.addEventListener('DOMContentLoaded', () => {
  const resetForm = document.getElementById('reset-form');
  const alertPlaceholder = document.getElementById('alert-placeholder'); // Still needed for append
  const resetView = document.getElementById('reset-view');
  const successView = document.getElementById('success-view');

  // showAlert, setValidation are now in utils.js

  resetForm.addEventListener('submit', async e => {
    e.preventDefault();
    alertPlaceholder.innerHTML = ''; // clearAlert is not needed as showAlert handles clearing

    const newPasswordInput = document.getElementById('reset-new-password');
    const confirmPasswordInput = document.getElementById('reset-confirm-password');
    const newPassword = newPasswordInput.value;
    const confirmPassword = confirmPasswordInput.value;

    // Client-side validation
    setValidation(newPasswordInput, null);
    setValidation(confirmPasswordInput, null);
    let isValid = true;

    if (newPassword.length < 6) {
      setValidation(newPasswordInput, 'Password must be at least 6 characters long.');
      isValid = false;
    }
    if (newPassword !== confirmPassword) {
      setValidation(confirmPasswordInput, 'Passwords do not match.');
      isValid = false;
    }
    if (!isValid) return;

    const params = new URLSearchParams(window.location.search);
    const token = params.get('token');
    const email = params.get('email');
    if (!token || !email) {
      showAlert('Invalid or expired password reset link.');
      return;
    }

    const submitBtn = resetForm.querySelector('button[type="submit"]');
    const originalBtnText = submitBtn.textContent;
    submitBtn.disabled = true;
    submitBtn.textContent = 'Resetting...';

    try {
      const r = await apiFetch('/api/v1/authenticate/confirm-password-reset', { method: 'POST', body: { token, email, newPassword } }, false);
      if (!r.ok) {
        const d = await r.json().catch(() => ({}));
        const m = d.errors ? d.errors.map(e => e.description).join(' ') : (d.message || 'Failed to reset password.');
        throw new Error(m);
      }
      resetView.classList.add('d-none');
      successView.classList.remove('d-none');
    } catch (err) {
      showAlert(err.message);
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = originalBtnText;
    }
});
