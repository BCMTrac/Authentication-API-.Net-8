document.addEventListener('DOMContentLoaded', () => {
    const API_BASE_URL = '/api/v1';
    const alertPlaceholder = document.getElementById('alert-placeholder');
    const mfaManagementView = document.getElementById('mfa-management-view');
    const changePasswordForm = document.getElementById('change-password-form');

    // Password Change Logic
    changePasswordForm?.addEventListener('submit', async e => {
        e.preventDefault();
        if(alertPlaceholder) alertPlaceholder.innerHTML = '';
        const currentPasswordInput = document.getElementById('current-password');
        const newPasswordInput = document.getElementById('new-password');
        const currentPassword = currentPasswordInput.value;
        const newPassword = newPasswordInput.value;

        setValidation(currentPasswordInput, null);
        setValidation(newPasswordInput, null);
        let isValid = true;
        if (!currentPassword) {
            setValidation(currentPasswordInput, 'Please enter your current password.');
            isValid = false;
        }
        if (newPassword.length < 12) {
            setValidation(newPasswordInput, 'New password must be at least 6 characters long.');
            isValid = false;
        }
        if (!isValid) return;

        const btn = changePasswordForm.querySelector('button[type="submit"]');
        const originalBtnText = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Updating...';

        try {
            const resp = await apiFetch('/authenticate/change-password', { method: 'POST', body: { currentPassword, newPassword } });
            if (!resp.ok) {
                const data = await resp.json().catch(() => ({}));
                throw new Error(data.message || 'Password change failed.');
            }
            showAlert('Password updated.', 'success');
            changePasswordForm.reset();
        } catch (err) {
            showAlert(err.message);
        } finally {
            btn.disabled = false;
            btn.innerHTML = originalBtnText;
        }
    });

    // MFA Management Logic (moved from mfa-management.js)
    async function fetchAndRenderMfaStatus() {
        try {
            const resp = await apiFetch('/users/me');
            if (!resp.ok) {
                const data = await resp.json().catch(() => ({}));
                throw new Error(data.message || 'Could not fetch user data.');
            }
            const user = await resp.json();
            initMfaManagement(mfaManagementView, user.mfaEnabled);
        } catch (err) {
            showAlert(err.message, 'warning');
        }
    }

    function initMfaManagement(mfaManagementView, isEnabled) {
        const render = () => {
            if (isEnabled) {
                mfaManagementView.innerHTML = `<div class="card"><div class="card-body"><h5 class="card-title">MFA is Enabled</h5><button id="disable-mfa-btn" class="btn btn-warning">Disable MFA</button><button id="regen-recovery-btn" class="btn btn-secondary ms-2">Regenerate Recovery Codes</button></div></div>`;
                document.getElementById('disable-mfa-btn').addEventListener('click', disableMfa);
                document.getElementById('regen-recovery-btn').addEventListener('click', regenerateRecoveryCodes);
            } else {
                mfaManagementView.innerHTML = `<div class="card"><div class="card-body"><h5 class="card-title">Enable Two-Factor Authentication</h5><p>Add an extra layer of security to your account.</p><button id="enable-mfa-btn" class="btn btn-success">Enable MFA</button><div id="mfa-enroll-flow" class="d-none mt-3"></div></div></div>`;
                document.getElementById('enable-mfa-btn').addEventListener('click', startMfaEnrollment);
            }
        };

        async function startMfaEnrollment(e) {
            handleApiAction(async () => {
                const resp = await apiFetch('/authenticate/mfa/enroll/start', { method: 'POST' });
                if (!resp.ok) {
                    const data = await resp.json().catch(() => ({}));
                    throw new Error(data.error || data.message || 'Could not start MFA enrollment.');
                }
                const data = await resp.json();
                const enroll = document.getElementById('mfa-enroll-flow');
                enroll.classList.remove('d-none');
                enroll.innerHTML = `<p>1. Scan this QR code with your authenticator app:</p><div class="text-center"><img src="${API_BASE_URL}/mfa/qr?otpauthUrl=${encodeURIComponent(data.otpauthUrl)}" alt="MFA QR Code"></div><p class="mt-3">2. Enter the code from your app to confirm:</p><form id="confirm-mfa-form"><div class="input-group mb-3"><input type="text" id="mfa-confirm-code" class="form-control" placeholder="6-digit code" required autocomplete="one-time-code"><button type="submit" class="btn btn-primary">Confirm & Enable</button></div></form>`;
                document.getElementById('confirm-mfa-form').addEventListener('submit', confirmMfaEnrollment);
                return resp;
            }, "MFA enrollment started.", e.currentTarget);
        }

        async function confirmMfaEnrollment(e) {
            e.preventDefault();
            const code = document.getElementById('mfa-confirm-code').value;
            const button = e.currentTarget.querySelector('button[type="submit"]');
            await handleApiAction(async () => {
                const resp = await apiFetch('/authenticate/mfa/enroll/confirm', { method: 'POST', body: { code } });
                if (!resp.ok) {
                    const data = await resp.json().catch(() => ({}));
                    throw new Error(data.error || data.message || 'Invalid MFA code.');
                }
                const data = await resp.json();
                mfaManagementView.innerHTML = `<div class="alert alert-success">MFA Enabled Successfully!</div><h5>Save these recovery codes!</h5><p>Store them somewhere safe. You can use them to access your account if you lose your device.</p><div class="recovery-codes p-3 bg-light rounded"></div><button id="mfa-done-btn" class="btn btn-primary mt-3">Done</button>`;
                const codesContainer = mfaManagementView.querySelector('.recovery-codes');
                data.recoveryCodes.forEach(code => { codesContainer.appendChild(document.createTextNode(code)); codesContainer.appendChild(document.createElement('br')); });
                document.getElementById('mfa-done-btn').addEventListener('click', render);
                return resp;
            }, null, button);
        }

        async function disableMfa(e) {
            try {
                if (!await showConfirmationModal('Disable MFA', 'Are you sure you want to disable Two-Factor Authentication?')) return;
            } catch { return; }

            await handleApiAction(async () => {
                const resp = await apiFetch('/authenticate/mfa/disable', { method: 'POST' });
                if (resp.ok) isEnabled = false;
                return resp;
            }, "MFA has been disabled.", e.currentTarget);
            render();
        }

        async function regenerateRecoveryCodes(e) {
            try {
                if (!await showConfirmationModal('Regenerate Recovery Codes', 'This will invalidate your old recovery codes. Are you sure?')) return;
            } catch { return; }

            await handleApiAction(async () => {
                const resp = await apiFetch('/authenticate/mfa/recovery/regenerate', { method: 'POST' });
                if (!resp.ok) throw new Error('Could not regenerate codes.');
                const data = await resp.json();
                const cardBody = mfaManagementView.querySelector('.card-body');
                cardBody.innerHTML = `<div class="alert alert-success">New Recovery Codes Generated!</div><h5>Save these new codes!</h5><div class="recovery-codes p-3 bg-light rounded"></div><button id="mfa-done-btn" class="btn btn-primary mt-3">Done</button>`;
                const codesContainer = cardBody.querySelector('.recovery-codes');
                data.recoveryCodes.forEach(code => { codesContainer.appendChild(document.createTextNode(code)); codesContainer.appendChild(document.createElement('br')); });
                document.getElementById('mfa-done-btn').addEventListener('click', render);
                return resp;
            }, null, e.currentTarget);
        }

        render();
    }

    // Initial fetch of MFA status when settings page loads
    fetchAndRenderMfaStatus();
});
