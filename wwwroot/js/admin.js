document.addEventListener('DOMContentLoaded', () => {

  async function handleApiAction(action, successMessage, buttonEl) {
    let originalBtnText = '';
    if (buttonEl) {
        originalBtnText = buttonEl.innerHTML;
        buttonEl.disabled = true;
        buttonEl.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
    }
    try {
        const response = await action();
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.message || errorData.error || 'The action failed.');
        }
        if (successMessage) {
            showAlert(successMessage, 'success');
        }
        await refreshSelectedUser();
    } catch (error) {
        showAlert(error.message);
    } finally {
        if (buttonEl) {
            buttonEl.disabled = false;
            buttonEl.innerHTML = originalBtnText;
        }
    }
  }

  function renderUserSessions(sessions) {
    sessionsTableBody.innerHTML = '';
    sessions.forEach(session => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="id-col"></td>
        <td></td>
        <td></td>
        <td></td>
        <td></td>
        <td class="ua-col"></td>
        <td class="text-end"><button class="btn btn-sm btn-outline-danger">Revoke</button></td>
      `;
      const cells = tr.querySelectorAll('td');
      cells[0].textContent = session.id;
      cells[1].textContent = formatDate(session.createdUtc);
      cells[2].textContent = formatDate(session.lastSeenUtc);
      cells[3].textContent = formatDate(session.revokedAtUtc);
      cells[4].textContent = session.ip ?? '';
      cells[5].textContent = session.userAgent ?? '';
      cells[5].title = session.userAgent ?? '';

      const revokeBtn = tr.querySelector('button');
      revokeBtn.addEventListener('click', async () => {
        try {
            const confirmed = await showConfirmationModal('Revoke Session', `Are you sure you want to revoke session ${session.id}?`, [
                { text: 'Cancel', class: 'btn btn-secondary', value: false },
                { text: 'Revoke Session', class: 'btn btn-danger', value: true }
            ]);
            if (!confirmed) return;
        } catch {
            return; 
        }
        handleApiAction(
            () => apiFetch(`${API.admin}/users/${selectedUserId}/sessions/${session.id}/revoke`, { method: 'POST' }),
            `Session ${session.id} revoked.`,
            revokeBtn
        );
      });
      sessionsTableBody.append(tr);
    });
  }

  //Event Listeners 

  searchBtn.addEventListener('click', (e) => {
    const query = encodeURIComponent((searchInput.value || '').trim());
    handleApiAction(async () => {
        const response = await apiFetch(`${API.admin}/users/search?q=${query}`);
        if (response.ok) {
            const users = await response.json();
            renderSearchResults(users);
        }
        return response;
    }, null, e.currentTarget);
  });
  searchInput.addEventListener('keydown', e => { if (e.key === 'Enter') searchBtn.click(); });

  inviteSendBtn?.addEventListener('click', (e) => {
    handleApiAction(
        () => apiFetch(`${API.auth}/invite`, { method: 'POST', body: { email, fullName, roles } }),
        'Invite sent successfully.',
        e.currentTarget
    ).then(() => { /* clear inputs */ });
  });

  roleAddBtn.addEventListener('click', (e) => {
    handleApiAction(
        () => apiFetch(`${API.admin}/users/${selectedUserId}/roles/add`, { method: 'POST', body: { role } }),
        `Role "${role}" added.`,
        e.currentTarget
    ).then(() => { roleInput.value = ''; });
  });

  tempPasswordBtn.addEventListener('click', (e) => {
    handleApiAction(
        () => apiFetch(`${API.admin}/users/${selectedUserId}/password/set-temporary`, { method: 'POST', body: { newPassword } }),
        'Temporary password has been set.',
        e.currentTarget
    ).then(() => { tempPasswordInput.value = ''; });
  });

  btnUnlock.addEventListener('click', (e) => {
    if (!selectedUserId) return;
    handleApiAction(() => apiFetch(`${API.admin}/users/${selectedUserId}/unlock`, { method: 'POST' }), 'User unlocked.', e.currentTarget);
  });

  btnLock.addEventListener('click', (e) => {
    if (!selectedUserId) return;
    handleApiAction(() => apiFetch(`${API.admin}/users/${selectedUserId}/lock`, { method: 'POST' }), 'User locked.', e.currentTarget);
  });

  btnConfirmEmail.addEventListener('click', (e) => {
    if (!selectedUserId) return;
    handleApiAction(() => apiFetch(`${API.admin}/users/${selectedUserId}/email/confirm`, { method: 'POST' }), 'Email confirmed for user.', e.currentTarget);
  });

  btnResendConfirm.addEventListener('click', (e) => {
    if (!selectedUserId) return;
    handleApiAction(() => apiFetch(`${API.admin}/users/${selectedUserId}/email/resend-confirm`, { method: 'POST' }), 'Confirmation email sent.', e.currentTarget);
  });

  btnBumpToken.addEventListener('click', (e) => {
    if (!selectedUserId) return;
    handleApiAction(() => apiFetch(`${API.admin}/users/${selectedUserId}/bump-token-version`, { method: 'POST' }), 'User token version bumped.', e.currentTarget);
  });

  btnSendReset.addEventListener('click', (e) => {
    if (!selectedUserId) return;
    handleApiAction(() => apiFetch(`${API.admin}/users/${selectedUserId}/password/reset-email`, { method: 'POST' }), 'Password reset email sent.', e.currentTarget);
  });

  btnDisableMfa.addEventListener('click', async (e) => {
    if (!selectedUserId) return;
    handleApiAction(() => apiFetch(`${API.admin}/users/${selectedUserId}/mfa/disable`, { method: 'POST' }), 'MFA has been disabled for the user.', e.currentTarget);
  });

  sessionsRevokeAllBtn.addEventListener('click', async (e) => {
    if (!selectedUserId) return;
    handleApiAction(() => apiFetch(`${API.admin}/users/${selectedUserId}/sessions/revoke-all`, { method: 'POST' }), 'All user sessions have been revoked.', e.currentTarget);
  });
});
