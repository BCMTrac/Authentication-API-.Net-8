document.addEventListener('DOMContentLoaded', () => {
    const resetForm = document.getElementById('reset-form');
    const alertPlaceholder = document.getElementById('alert-placeholder');
    const resetView = document.getElementById('reset-view');
    const successView = document.getElementById('success-view');

    function showAlert(message, type = 'danger') {
        const wrapper = document.createElement('div');
        wrapper.innerHTML = [
            `<div class="alert alert-${type} alert-dismissible" role="alert">`,
            `   <div>${message}</div>`,
            '   <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>',
            '</div>'
        ].join('');
        alertPlaceholder.append(wrapper);
    }

    resetForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        alertPlaceholder.innerHTML = '';

        const newPassword = document.getElementById('reset-new-password').value;
        const confirmPassword = document.getElementById('reset-confirm-password').value;

        if (newPassword !== confirmPassword) {
            showAlert('Passwords do not match.');
            return;
        }

        const params = new URLSearchParams(window.location.search);
        const token = params.get('token');
        const email = params.get('email');

        if (!token || !email) {
            showAlert('Invalid or expired password reset link.');
            return;
        }

        const body = { token, email, newPassword };

        try {
            const response = await fetch('/api/v1/authenticate/confirm-password-reset', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });

            if (!response.ok) {
                const data = await response.json();
                const errorMsg = data.errors ? data.errors.map(e => e.description).join(' ') : (data.message || 'Failed to reset password.');
                throw new Error(errorMsg);
            }

            resetView.classList.add('d-none');
            successView.classList.remove('d-none');

        } catch (error) {
            showAlert(error.message);
        }
    });
});

