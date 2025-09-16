document.addEventListener('DOMContentLoaded', () => {
    const API_BASE_URL = '/api/v1';
    const adminLoginView = document.getElementById('admin-login-view');
    const passwordLoginForm = document.getElementById('password-login-form');
    const showPasswordLoginLink = document.getElementById('show-password-login');
    const adminMfaInputContainer = document.getElementById('admin-mfa-input-container');
    const alertPlaceholder = document.getElementById('alert-placeholder'); // Still needed for append

    const googleLoginBtn = document.getElementById('google-login');
    const microsoftLoginBtn = document.getElementById('microsoft-login');
    const adminUseRecoveryBtn = document.getElementById('admin-use-recovery'); // New element

    async function apiFetch(endpoint, options = {}) {
        const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
        const currentTokens = loadTokens(); // Load tokens from utils.js
        if (currentTokens.token) headers['Authorization'] = `Bearer ${currentTokens.token}`;
        const res = await fetch(`${API_BASE_URL}${endpoint}`, { ...options, headers, body: options.body ? JSON.stringify(options.body) : null });
        // Admin login flow might not need refresh token logic here, as it's a dedicated login.
        // If 401, it means login failed or session expired, user needs to re-login.
        return res;
    }

    // --- OTP helpers ---
    function collectOtp(){
        const boxes = adminMfaInputContainer.querySelectorAll('.otp');
        return Array.from(boxes).map(i=>i.value.trim()).join('');
    }
    function resetOtp(){
        const boxes = adminMfaInputContainer.querySelectorAll('.otp');
        boxes.forEach(b=>b.value='');
        if (boxes[0]) boxes[0].focus();
    }
    adminMfaInputContainer.querySelectorAll?.('.otp').forEach((el, idx, arr)=>{
        el.addEventListener('input', ()=>{ if(el.value && idx < arr.length-1) arr[idx+1].focus(); });
        el.addEventListener('keydown', (e)=>{ if(e.key==='Backspace' && !el.value && idx>0) arr[idx-1].focus(); });
    });

    // --- SSO Login Functions ---
    function googleReady() {
        if (!window.GOOGLE_CLIENT_ID || typeof google === 'undefined' || !google?.accounts?.id) return false;
        google.accounts.id.initialize({
            client_id: window.GOOGLE_CLIENT_ID,
            callback: async (resp) => {
                if (!resp || !resp.credential) return;
                try {
                    const r = await apiFetch('/authenticate/google', { method: 'POST', body: { idToken: resp.credential } });
                    if (!r.ok) {
                        const data = await r.json().catch(() => ({}));
                        throw new Error(data.message || 'Google sign-in failed.');
                    }
                    const data = await r.json();
                    if (data.token) {
                        saveTokens(data.token, data.refreshToken);
                        window.location.href = '/admin'; // Redirect to admin dashboard
                    }
                } catch (err) {
                    showAlert(err.message || 'Google sign-in failed.');
                }
            }
        });
        return true;
    }

    function microsoftReady() {
        // This is a placeholder. Actual Microsoft SSO integration requires MSAL.js library.
        // For now, it will just show a message.
        showAlert('Microsoft SSO integration is not yet fully implemented. Please use email/password.', 'info');
        return false; // Indicate not ready
    }

    //Event Listeners
    showPasswordLoginLink.addEventListener('click', (e) => {
        e.preventDefault();
        passwordLoginForm.classList.toggle('d-none');
        showPasswordLoginLink.classList.toggle('d-none');
    });

    passwordLoginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        //Clear previous alerts and validation
        alertPlaceholder.innerHTML = '';
        const emailInput = document.getElementById('admin-login-email');
        const passwordInput = document.getElementById('admin-login-password');
        const email = emailInput.value.trim();
        const password = passwordInput.value;

        setValidation(emailInput, null);
        setValidation(passwordInput, null);
        let isValid = true;

        if (!isValidEmail(email)) {
            setValidation(emailInput, 'Please enter a valid work email address.');
            isValid = false;
        }
        if (!password) {
            setValidation(passwordInput, 'Password is required.');
            isValid = false;
        }
        if (!isValid) return;

        // Store password temporarily for MFA step
        window._adminLoginPassword = password;

        const btn = passwordLoginForm.querySelector('.btn-cta');
        const text = btn.querySelector('.btn-text');
        const spinner = btn.querySelector('.btn-spinner');
        btn.disabled = true; spinner.classList.remove('d-none'); text.textContent = 'Signing in…';

        try {
            const res = await apiFetch('/authenticate/login', { method: 'POST', body: { identifier: email, password: password, mfaCode: null } }); // MFA code will be handled in a separate step
            const data = await res.json().catch(() => ({}));

            if (res.ok && data.mfaRequired) {
                adminMfaInputContainer.classList.remove('d-none');
                passwordLoginForm.classList.add('d-none'); 
                resetOtp();
                showAlert('Enter your authenticator code to continue.', 'info');
                return;
            }
            if (!res.ok) {
                const errorMsg = data.error || data.message || 'Sign-in failed. Please check your credentials.';
                throw new Error(errorMsg);
            }
            if (data.token) {
                saveTokens(data.token, data.refreshToken);
                window.location.href = '/admin'; // Redirect to admin dashboard
                return;
            }
            throw new Error('Unexpected response.');

        } catch (err) {
            showAlert(err.message || 'Sign-in failed.');
        } finally {
            btn.disabled = false; spinner.classList.add('d-none'); text.textContent = 'Continue';
        }
    });

    // MFA verification for password login
    adminMfaInputContainer.querySelector('.btn-cta')?.addEventListener('click', async (e) => {
        e.preventDefault();
        const mfaCode = collectOtp();
        if (!mfaCode || mfaCode.length !== 6) {
            showAlert('Please enter a 6-digit MFA code.', 'warning');
            return;
        }

        const btn = adminMfaInputContainer.querySelector('.btn-cta');
        const text = btn.querySelector('.btn-text');
        const spinner = btn.querySelector('.btn-spinner');
        btn.disabled = true; spinner.classList.remove('d-none'); text.textContent = 'Verifying…';

        try {
            // Re-attempt login with MFA code
            const email = document.getElementById('admin-login-email').value.trim();
            const password = window._adminLoginPassword || ''; // Use stored password for MFA step
            const res = await apiFetch('/authenticate/login', { method: 'POST', body: { identifier: email, password: password, mfaCode: mfaCode } });
            const data = await res.json().catch(() => ({}));

            if (!res.ok) {
                const errorMsg = data.error || data.message || 'MFA verification failed.';
                throw new Error(errorMsg);
            }
            if (data.token) {
                saveTokens(data.token, data.refreshToken);
                window.location.href = '/admin'; // Redirect to admin dashboard
                return;
            }
            throw new Error('Unexpected MFA response.');

        } catch (err) {
            showAlert(err.message || 'MFA verification failed.');
        } finally {
            btn.disabled = false; spinner.classList.add('d-none'); text.textContent = 'Verify MFA';
        }
    });

    //Recovery Code Logic
    adminUseRecoveryBtn?.addEventListener('click', async () => {
        const recoveryCode = await showPromptModal('Enter Recovery Code', 'Please enter one of your recovery codes:', '');
        if (!recoveryCode) return; //User cancelled

        const btn = adminUseRecoveryBtn; //Use the recovery button itself for spinner
        const originalText = btn.textContent;
        btn.disabled = true; btn.textContent = 'Verifying...';

        try {
            const email = document.getElementById('admin-login-email').value.trim();
            // Password is not needed for recovery code login
            const res = await apiFetch('/authenticate/login', { method: 'POST', body: { identifier: email, recoveryCode: recoveryCode } });
            const data = await res.json().catch(() => ({}));

            if (!res.ok) {
                const errorMsg = data.error || data.message || 'Recovery code verification failed.';
                throw new Error(errorMsg);
            }
            if (data.token) {
                saveTokens(data.token, data.refreshToken);
                window.location.href = '/admin'; 
                return;
            }
            throw new Error('Unexpected recovery code response.');
        } catch (err) {
            showAlert(err.message || 'Recovery code verification failed.');
        } finally {
            btn.disabled = false; btn.textContent = originalText;
        }
    });


    // Wire up SSO buttons
    googleLoginBtn?.addEventListener('click', () => {
        if (googleReady()) {
            try {
                google.accounts.id.prompt();
            } catch {
                showAlert('Google prompt blocked. Check popup settings.', 'warning');
            }
        } else {
            showAlert('Google Sign-In not configured.', 'info');
        }
    });

    microsoftLoginBtn?.addEventListener('click', () => {
        if (microsoftReady()) {
            // Microsoft SSO flow would be initiated here
        }
        else {
            showAlert('Microsoft Sign-In not configured or ready.', 'info');
        }
    });
});
