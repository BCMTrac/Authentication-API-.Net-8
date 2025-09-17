/* schemes-select.js */
(function(){
  if(!localStorage.getItem('auth_token')){ window.location.href='/login'; return; }
  const dn = document.getElementById('displayName'); if(dn) dn.textContent=localStorage.getItem('auth_username')||'User';
  const body = document.getElementById('schemeRows'); if(!body) return;
  const schemes=[
    {name:'Waterfront Office Park Association',type:'HOA'},
    {name:'The Jameson Body Corporate',type:'BC'},
    {name:'Stellenbosch Manor Body Corporate',type:'BC'},
    {name:'Southdale Mews Body Corporate',type:'BC'},
    {name:'Seven Oaks Body Corporate',type:'BC'},
    {name:'Santa Fe Body Corporate',type:'BC'},
    {name:'Mindalore Villas Body Corporate',type:'BC'},
    {name:'Crystal Rock Body Corporate',type:'BC'},
    {name:'Cottonwood Lane Body Corporate',type:'BC'},
    {name:'Cotswold Body Corporate',type:'BC'}
  ];
  schemes.forEach(s=>{ const row=document.createElement('div'); row.className='scheme-row'; row.innerHTML=`<div class="col name">${s.name}</div><div class="col type">${s.type}</div>`; row.addEventListener('click',()=>{document.querySelectorAll('.scheme-row').forEach(r=>r.classList.remove('selected')); row.classList.add('selected'); localStorage.setItem('auth_scheme', s.name); document.getElementById('continueScheme').disabled=false;}); body.appendChild(row); });
  document.getElementById('continueScheme')?.addEventListener('click',()=>{ const scheme=localStorage.getItem('auth_scheme'); if(scheme){ alert('Accessing '+scheme+' as '+(localStorage.getItem('auth_role')||'N/A')); }});
})();