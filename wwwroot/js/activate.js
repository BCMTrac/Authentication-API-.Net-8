document.addEventListener('DOMContentLoaded', () => {
  const activateForm = document.getElementById('activate-form');
  const view = document.getElementById('activate-view');
  const success = document.getElementById('activate-success');
  const alertPlaceholder = document.getElementById('alert-placeholder');
  function showAlert(m,t){ const w=document.createElement('div'); w.innerHTML=[`<div class="alert alert-${t||'danger'} alert-dismissible" role="alert">`,`<div>${m}</div>`,`<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>`,`</div>`].join(''); alertPlaceholder.innerHTML=''; alertPlaceholder.append(w);} 
  const params = new URLSearchParams(window.location.search); const token=params.get('token'); const email=params.get('email'); if(!token||!email){ showAlert('Invalid or expired activation link.'); }
  activateForm.addEventListener('submit', async e => {
    e.preventDefault(); alertPlaceholder.innerHTML='';
    if(!token||!email){ showAlert('Invalid or expired activation link.'); return; }
    const fullName = document.getElementById('act-fullname').value.trim();
    const password = document.getElementById('act-password').value;
    const ok = document.getElementById('act-terms').checked; if(!ok){ showAlert('Please accept the terms.'); return; }
    try{
      const r = await fetch('/api/v1/authenticate/activate', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ email, token, password, fullName })});
      if(!r.ok){ const d=await r.json().catch(()=>({})); throw new Error(d.error||d.message||'Activation failed.'); }
      view.classList.add('d-none'); success.classList.remove('d-none');
    }catch(err){ showAlert(err.message); }
  });
});

