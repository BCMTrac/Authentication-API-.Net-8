// /js/modal.js

/**
 * Shows a confirmation modal.
 * @param {string} title The title of the modal.
 * @param {string} body The HTML content of the modal body.
 * @param {Array<{text: string, class: string, value: any}>} buttons Array of button definitions.
 * @returns {Promise<any>} A promise that resolves with the 'value' of the clicked button, or rejects if the modal is dismissed.
 */
function showConfirmationModal(title, body, buttons = []) {
  return new Promise((resolve, reject) => {
    const modalElement = document.getElementById('app-modal');
    if (!modalElement) return reject('Modal element not found in DOM.');

    const modal = new bootstrap.Modal(modalElement);

    document.getElementById('app-modal-label').textContent = title;
    document.getElementById('app-modal-body').innerHTML = body;

    const footer = document.getElementById('app-modal-footer');
    footer.innerHTML = '';

    buttons.forEach(btnDef => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = btnDef.class || 'btn btn-secondary';
      button.textContent = btnDef.text;
      button.addEventListener('click', () => {
        resolve(btnDef.value);
        modal.hide();
      });
      footer.appendChild(button);
    });

    modalElement.addEventListener('hidden.bs.modal', () => {
      reject('Modal dismissed');
    }, { once: true });

    modal.show();
  });
}

/**
 * Shows a prompt modal with an input field.
 * @param {string} title The title of the modal.
 * @param {string} body The HTML content to show above the input.
 * @param {string} initialValue The initial value for the input field.
 * @returns {Promise<string|null>} A promise that resolves with the input value, or null if cancelled.
 */
function showPromptModal(title, body, initialValue = '') {
    // Create a temporary element to safely set the body text and then get its HTML
    const tempP = document.createElement('p');
    tempP.textContent = body; // Use textContent to prevent XSS
    const safeBodyHtml = tempP.outerHTML;

    const bodyHtml = `
        ${safeBodyHtml}
        <input type="text" class="form-control" id="modal-prompt-input" value="${initialValue}">
    `;

    const buttons = [
        { text: 'Cancel', class: 'btn btn-secondary', value: null },
        { text: 'OK', class: 'btn btn-primary', value: 'ok' }
    ];

    return new Promise((resolve, reject) => {
        showConfirmationModal(title, bodyHtml, buttons)
            .then(result => {
                if (result === 'ok') {
                    const input = document.getElementById('modal-prompt-input');
                    resolve(input.value);
                } else {
                    resolve(null); // Cancelled
                }
            })
            .catch(() => resolve(null)); // Dismissed
        
        const modalElement = document.getElementById('app-modal');
        modalElement.addEventListener('shown.bs.modal', () => {
            document.getElementById('modal-prompt-input')?.focus();
        }, { once: true });
    });
}