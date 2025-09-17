/* roles-select.js */
(function(){
  if(!localStorage.getItem('auth_token')){ window.location.href='/login'; return; }
  const name = localStorage.getItem('auth_username')||'User';
  const dn = document.getElementById('displayName'); if(dn) dn.textContent=name;
  const container = document.getElementById('roleButtons');
  if(!container) return;
  try {
    const token = localStorage.getItem('auth_token');
    const payload = JSON.parse(atob(token.split('.')[1]));
    let roles = payload['role'];
    if(!roles) roles=[]; else if(!Array.isArray(roles)) roles=[roles];
    if(roles.length===0){ container.innerHTML='<p class="muted">No roles assigned.</p>'; }
    roles.forEach(r=>{
      const btn=document.createElement('button'); btn.type='button'; btn.textContent=r; btn.className='role-btn';
      btn.addEventListener('click',()=>{
        document.querySelectorAll('#roleButtons button').forEach(b=>b.classList.remove('selected'));
        btn.classList.add('selected');
        localStorage.setItem('auth_role', r);
        document.getElementById('continueRoles').disabled=false;
      });
      container.appendChild(btn);
    });
  }catch{}
  document.getElementById('continueRoles')?.addEventListener('click',()=>{window.location.href='/schemes-select';});
})();