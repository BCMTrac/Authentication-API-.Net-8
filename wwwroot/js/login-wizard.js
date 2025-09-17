/* Login Wizard JS: handles steps, API calls, role & scheme selection */
(function(){
    const stateKey = 'loginWizardState';
    const saveState = (data) => localStorage.setItem(stateKey, JSON.stringify(data));
    const loadState = () => { try { return JSON.parse(localStorage.getItem(stateKey)||'{}'); } catch { return {}; } };
    const clearState = () => localStorage.removeItem(stateKey);

    const api = async (url, opts={}) => {
        const res = await fetch(url, Object.assign({ headers: { 'Content-Type':'application/json' }}, opts));
        if(!res.ok){ throw new Error('Request failed: '+res.status); }
        if(res.status === 204) return null; return res.json().catch(()=>null);
    };

    const step = window.LoginWizard?.currentStep;
    const state = loadState();

    if(step === 1){
        document.body.classList.add('login-wizard');
        const form = document.getElementById('loginForm');
        form?.addEventListener('submit', async e => {
            e.preventDefault();
            const username = form.username.value.trim();
            const password = form.password.value;
            if(!username || !password) return;
            const btn = document.getElementById('loginBtn');
            btn.disabled = true; btn.textContent = 'Authenticating…';
            try {
                // Authenticate (adjust endpoint if using email)
                const resp = await api('/api/v1/authenticate/login', { method:'POST', body: JSON.stringify({ identifier: username, password, mfaCode:null }) });
                // store token + user basic (decode JWT optionally) - but better call me endpoint
                if(resp?.token){
                    state.token = resp.token;
                    saveState(state);
                    // fetch user info (implement endpoint if needed). For now minimal decode.
                    const payload = JSON.parse(atob(resp.token.split('.')[1]));
                    state.userName = payload['unique_name'] || username;
                    saveState(state);
                    window.location.href = '/Login/Step2Roles';
                }
            }catch(err){
                alert('Login failed');
            }finally{ btn.disabled = false; btn.textContent = 'Login'; }
        });
    }

    if(step === 2){
        document.body.classList.add('login-wizard');
        if(!state.token){ window.location.href = '/Login/Step1'; return; }
        document.getElementById('displayName').textContent = state.userName || 'User';
        // Ideally fetch roles from token claims 'role'
        try {
            const payload = JSON.parse(atob(state.token.split('.')[1]));
            const roles = (Array.isArray(payload['role']) ? payload['role'] : (payload['role']? [payload['role']] : []));
            const container = document.getElementById('roleButtons');
            if(roles.length === 0){ container.innerHTML = '<p class="muted">No roles found on your account.</p>'; }
            roles.forEach(r => {
                const btn = document.createElement('button');
                btn.type='button';
                btn.textContent = r;
                btn.addEventListener('click', () => {
                    document.querySelectorAll('#roleButtons button').forEach(b=>b.classList.remove('selected'));
                    btn.classList.add('selected');
                    state.selectedRole = r; saveState(state);
                    document.getElementById('continueRoles').disabled = false;
                });
                container.appendChild(btn);
            });
        }catch{ /* ignore */ }
        document.getElementById('continueRoles')?.addEventListener('click', ()=>{
            window.location.href = '/Login/Step3Schemes';
        });
    }

    if(step === 3){
        document.body.classList.add('login-wizard');
        if(!state.token){ window.location.href = '/Login/Step1'; return; }
        document.getElementById('displayName').textContent = state.userName || 'User';
        // Fetch schemes - placeholder static list; replace with real endpoint when available
        const schemes = [
            { name:'Waterfront Office Park Association', type:'HOA' },
            { name:'The Jameson Body Corporate', type:'BC' },
            { name:'Stellenbosch Manor Body Corporate', type:'BC' },
            { name:'Southdale Mews Body Corporate', type:'BC' },
            { name:'Seven Oaks Body Corporate', type:'BC' },
            { name:'Santa Fe Body Corporate', type:'BC' },
            { name:'Mindalore Villas Body Corporate', type:'BC' },
            { name:'Crystal Rock Body Corporate', type:'BC' },
            { name:'Cottonwood Lane Body Corporate', type:'BC' },
            { name:'Cotswold Body Corporate', type:'BC' }
        ];
        const body = document.getElementById('schemeRows');
        schemes.forEach(s => {
            const row = document.createElement('div');
            row.className = 'scheme-row';
            row.innerHTML = `<div class="col name">${s.name}</div><div class="col type">${s.type}</div>`;
            row.addEventListener('click', () => {
                document.querySelectorAll('.scheme-row').forEach(r=>r.classList.remove('selected'));
                row.classList.add('selected');
                state.selectedScheme = s.name; saveState(state);
                document.getElementById('continueScheme').disabled = false;
            });
            body.appendChild(row);
        });
        document.getElementById('continueScheme')?.addEventListener('click', ()=>{
            if(state.selectedScheme){
                alert('Accessing: '+ state.selectedScheme + '\nRole: '+ (state.selectedRole||'N/A'));
                clearState();
            }
        });
    }
})();