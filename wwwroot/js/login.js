/* login.js */
(function(){
  const form = document.getElementById('loginForm');
  if(!form) return;
  const api = async (url, data) => {
    const res = await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
    if(!res.ok) throw new Error('HTTP '+res.status); return res.json();
  };
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    if(!username||!password) return;
    const btn = document.getElementById('loginBtn');
    btn.disabled = true; const original = btn.textContent; btn.textContent='Signing in…';
    try {
      const resp = await api('/api/v1/authenticate/login',{identifier:username,password:password,mfaCode:null});
      if(resp && resp.token){
        localStorage.setItem('auth_token', resp.token);
        const payload = JSON.parse(atob(resp.token.split('.')[1]));
        localStorage.setItem('auth_username', payload['unique_name']||username);
        window.location.href = '/roles-select';
      }
    } catch(err){ alert('Login failed'); }
    finally { btn.disabled=false; btn.textContent=original; }
  });
})();