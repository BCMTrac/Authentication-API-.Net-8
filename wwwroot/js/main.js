document.addEventListener('DOMContentLoaded', () => {
    const loginView = document.getElementById('login-view');
    const forgotPasswordView = document.getElementById('forgot-password-view');
    const loggedInView = document.getElementById('logged-in-view');
    const views = [loginView, forgotPasswordView, loggedInView];

    const loginForm = document.getElementById('login-form');
    const forgotPasswordForm = document.getElementById('forgot-password-form');
    const showForgotPasswordLink = document.getElementById('show-forgot-password');
    const showLoginFromForgotLink = document.getElementById('show-login-from-forgot');
    const googleBtn = document.getElementById('google-login');
    const logoutButton = document.getElementById('logout-button');
    const logoutAllButton = document.getElementById('logout-all-button');
    const magicLinkStart = document.getElementById('magic-link-start');
    const mfaInputContainer = document.getElementById('mfa-input-container');
    const alertPlaceholder = document.getElementById('alert-placeholder');
    const userInfo = document.getElementById('user-info');

    function switchView(targetView) {
        views.forEach(v => v.classList.toggle('d-none', v.id !== targetView));
        if(alertPlaceholder) alertPlaceholder.innerHTML = '';
    }

    // View toggles
    showForgotPasswordLink.addEventListener('click', e => { e.preventDefault(); switchView('forgot-password-view'); });
    showLoginFromForgotLink.addEventListener('click', e => { e.preventDefault(); switchView('login-view'); });

    // OTP helpers
    function collectOtp(){
        const boxes = mfaInputContainer.querySelectorAll('.otp');
        return Array.from(boxes).map(i=>i.value.trim()).join('');
    }
    function resetOtp(){
        const boxes = mfaInputContainer.querySelectorAll('.otp');
        boxes.forEach(b=>b.value='');
        if (boxes[0]) boxes[0].focus();
    }
    mfaInputContainer.querySelectorAll?.('.otp').forEach((el, idx, arr)=>{
        el.addEventListener('input', ()=>{ if(el.value && idx < arr.length-1) arr[idx+1].focus(); });
        el.addEventListener('keydown', (e)=>{ if(e.key==='Backspace' && !el.value && idx>0) arr[idx-1].focus(); });
    });

    // Login flow (email/password -> optional MFA)
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        if(alertPlaceholder) alertPlaceholder.innerHTML = '';
        const tenantCodeInput = document.getElementById('tenant-code');
        const tenantCode = tenantCodeInput.value.trim();
        const identifierInput = document.getElementById('login-identifier');
        const identifier = identifierInput.value.trim();
        const password = document.getElementById('login-password').value;

        setValidation(tenantCodeInput, null);
        setValidation(identifierInput, null);
        let isValid = true;

        if (!tenantCode) {
            setValidation(tenantCodeInput, 'Estate code is required.');
            isValid = false;
        }
        if (!identifier || !password) {
            showAlert('Please enter both your identifier and password.', 'warning');
            isValid = false;
        }
        if (identifier.includes('@') && !isValidEmail(identifier)) {
            setValidation(identifierInput, 'Please enter a valid email address.');
            isValid = false;
        }
        if (!isValid) return;

        let mfaCode = undefined;
        if (!mfaInputContainer.classList.contains('d-none')) {
            const otp = collectOtp();
            if (otp && otp.length === 6) mfaCode = otp;
        }
        const btn = loginForm.querySelector('.btn-cta');
        const text = btn.querySelector('.btn-text');
        const spinner = btn.querySelector('.btn-spinner');
        btn.disabled = true; spinner.classList.remove('d-none'); text.textContent = 'Signing in…';
        try {
            const res = await apiFetch('/authenticate/login', { method: 'POST', body: { tenantCode, identifier, password, mfaCode } });
            const data = await res.json().catch(() => ({}));
            if (res.ok && data.mfaRequired) {
                mfaInputContainer.classList.remove('d-none');
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
                showDashboard();
                return;
            }
            throw new Error('Unexpected response.');
        } catch (err) {
            showAlert(err.message || 'Sign-in failed.');
            loginView.classList.add('animate-pop'); setTimeout(() => loginView.classList.remove('animate-pop'), 220);
        } finally {
            btn.disabled = false; spinner.classList.add('d-none'); text.textContent = 'Sign in';
        }
    });

    // Forgot password
    forgotPasswordForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        if(alertPlaceholder) alertPlaceholder.innerHTML = '';
        const emailInput = document.getElementById('forgot-email');
        const email = emailInput.value.trim();

        setValidation(emailInput, null);
        if (!isValidEmail(email)) {
            setValidation(emailInput, 'Please enter a valid email address.');
            return;
        }

        try {
            const res = await apiFetch('/authenticate/request-password-reset', { method: 'POST', body: { email } });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                throw new Error(data.message || 'Could not send reset link.');
            }
            showAlert('If this email exists, a reset link has been sent.', 'success');
        } catch (err) { showAlert(err.message); }
    });

    // Magic link start
    magicLinkStart?.addEventListener('click', async (e) => {
        e.preventDefault();
        if(alertPlaceholder) alertPlaceholder.innerHTML = '';
        let email = document.getElementById('login-identifier').value.trim();
        if (!email || !email.includes('@')) {
            email = await showPromptModal('Magic Sign-In', 'Enter your email address to receive a magic sign-in link:', email);
        }
        if (!email) return;
        email = email.trim();
        if (!email) return;

        try {
            const r = await apiFetch('/authenticate/magic/start', { method: 'POST', body: { email } });
            if (!r.ok) {
                const data = await r.json().catch(() => ({}));
                throw new Error(data.message || 'Could not send magic link.');
            }
            showAlert('If this email exists, a one-time sign-in link was sent.', 'success');
        } catch (err) { showAlert(err.message); }
    });

    // Google SSO
    function googleReady(){
        if(!window.GOOGLE_CLIENT_ID || typeof google === 'undefined' || !google?.accounts?.id) return false;
        google.accounts.id.initialize({ client_id: window.GOOGLE_CLIENT_ID, callback: async (resp)=>{
            if(!resp || !resp.credential) return;
            try{ const r = await apiFetch('/authenticate/google', { method:'POST', body:{ idToken: resp.credential } });
                if(!r.ok) {
                    const data = await r.json().catch(()=>({}));
                    throw new Error(data.message || 'Google sign-in failed.');
                }
                const data = await r.json();
                if(data.token){ saveTokens(data.token, data.refreshToken); showDashboard(); }
            }catch(err){ showAlert(err.message || 'Google sign-in failed.'); }
        }});
        return true;
    }
    googleBtn?.addEventListener('click', ()=>{ if(googleReady()){ try{ google.accounts.id.prompt(); } catch{ showAlert('Google prompt blocked. Check popup settings.','warning'); } } else { showAlert('Google Sign-In not configured.','info'); } });

    // Handle magic link verify via query params
    (function(){
        const params = new URLSearchParams(window.location.search);
        const token = params.get('magicToken');
        const email = params.get('email');
        if(token && email){
            (async()=>{
                try{ const r = await apiFetch('/authenticate/magic/verify',{ method:'POST', body:{ email, token } });
                    if(!r.ok) {
                        const data = await r.json().catch(()=>({}));
                        throw new Error(data.message || 'Magic link invalid or expired.');
                    }
                    const data = await r.json();
                    if(data.token){ saveTokens(data.token, data.refreshToken); window.history.replaceState({}, document.title, window.location.pathname); showDashboard(); }
                }catch(err){ showAlert(err.message); }
            })();
        }
    })();

    // Logout flows
    async function handleLogout() {
        const tokens = loadTokens();
        try {
            if (tokens.refreshToken) {
                await apiFetch('/authenticate/logout', { method: 'POST', body: { refreshToken: tokens.refreshToken } });
            } else {
                await apiFetch('/authenticate/logout', { method: 'POST', body: {} });
            }
        } catch(e){
			// Log silently
        } finally {
            clearTokens();
            switchView('login-view');
        }
    }
    logoutButton?.addEventListener('click', handleLogout);
    logoutAllButton?.addEventListener('click', async ()=>{
        try {
            await apiFetch('/authenticate/logout-all', { method:'POST' });
        } catch(e){
            // Log silently
        }
        await handleLogout();
    });

    // Dashboard rendering
    async function showDashboard() {
        switchView('logged-in-view');
        try {
            const resp = await apiFetch('/users/me');
            if (!resp.ok) {
                const data = await resp.json().catch(() => ({}));
                throw new Error(data.message || 'Could not fetch user data.');
            }
            const user = await resp.json();
            userInfo.innerHTML = '';
            const userP = document.createElement('p');
            userP.innerHTML = '<strong>Username:</strong> ';
            userP.appendChild(document.createTextNode(user.userName));
            
            const emailP = document.createElement('p');
            emailP.innerHTML = '<strong>Email:</strong> ';
            emailP.appendChild(document.createTextNode(`${user.email} (${user.emailConfirmed ? 'Verified' : 'Not Verified'})`));

            const mfaP = document.createElement('p');
            mfaP.innerHTML = '<strong>MFA Enabled:</strong> ';
            mfaP.appendChild(document.createTextNode(user.mfaEnabled ? 'Yes' : 'No'));

            userInfo.append(userP, emailP, mfaP);
        } catch (err) { showAlert(err.message, 'warning'); }
    }

    function init() {
        const initialTokens = loadTokens();
        if (initialTokens.token) {
            showDashboard();
        } else {
            switchView('login-view');
        }

        const rememberMeCheckbox = document.getElementById('remember-me');
        const trustDeviceCheckbox = document.getElementById('trust-device');
        if (rememberMeCheckbox) {
            rememberMeCheckbox.checked = localStorage.getItem('rememberMe') === 'true';
            rememberMeCheckbox.addEventListener('change', (e) => {
                localStorage.setItem('rememberMe', e.target.checked);
            });
        }
        if (trustDeviceCheckbox) {
            trustDeviceCheckbox.checked = localStorage.getItem('trustDevice') === 'true';
            trustDeviceCheckbox.addEventListener('change', (e) => {
                localStorage.setItem('trustDevice', e.target.checked);
            });
        }
    }
    init();
});