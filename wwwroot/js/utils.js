// wwwroot/js/utils.js

const API_BASE_URL = '/api/v1';

/**
 * Displays an alert message to the user.
 * @param {string} message The message to display.
 * @param {string} [type='danger'] The type of alert (e.g., 'success', 'info', 'warning', 'danger').
 */
function showAlert(message, type = 'danger') {
    const alertPlaceholder = document.getElementById('alert-placeholder');
    if (!alertPlaceholder) {
        return;
    }
    const wrapper = document.createElement('div');
    const messageDiv = document.createElement('div');
    messageDiv.textContent = message; // Use textContent to prevent XSS
    wrapper.innerHTML = `<div class="alert alert-${type} alert-dismissible" role="alert"></div>`;
    const alertDiv = wrapper.firstChild;
    alertDiv.appendChild(messageDiv);
    alertDiv.insertAdjacentHTML('beforeend', '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>');
    alertPlaceholder.innerHTML = '';
    alertPlaceholder.append(alertDiv);
}

/**
 * Validates if a string is a well-formed email address.
 * @param {string} email The email string to validate.
 * @returns {boolean} True if the email is valid, false otherwise.
 */
function isValidEmail(email) {
    const re = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(String(email).toLowerCase());
}

/**
 * Sets or clears validation feedback for an input element.
 * @param {HTMLElement} inputElement The input element to validate.
 * @param {string|null} message The validation message to display, or null to clear validation.
 */
function setValidation(inputElement, message) {
    const feedbackElement = inputElement.nextElementSibling;
    if (message) {
        inputElement.classList.add('is-invalid');
        if (feedbackElement && feedbackElement.classList.contains('invalid-feedback')) {
            feedbackElement.textContent = message;
        }
    } else {
        inputElement.classList.remove('is-invalid');
        if (feedbackElement && feedbackElement.classList.contains('invalid-feedback')) {
            feedbackElement.textContent = '';
        }
    }
}

/**
 * Saves authentication tokens to localStorage.
 * @param {string} token The access token.
 * @param {string} refreshToken The refresh token.
 */
function saveTokens(token, refreshToken) {
    localStorage.setItem('auth_token', token);
    if (refreshToken) localStorage.setItem('refresh_token', refreshToken);
}

/**
 * Loads authentication tokens from localStorage.
 * @returns {{token: string|null, refreshToken: string|null}}
 */
function loadTokens() {
    return {
        token: localStorage.getItem('auth_token'),
        refreshToken: localStorage.getItem('refresh_token')
    };
}

/**
 * Clears authentication tokens from localStorage.
 */
function clearTokens() {
    localStorage.removeItem('auth_token');
    localStorage.removeItem('refresh_token');
}

/**
 * A wrapper for the fetch API that handles token refresh automatically.
 * @param {string} endpoint The API endpoint (e.g., '/users/me').
 * @param {object} [options={}] Fetch options.
 * @returns {Promise<Response>}
 */
async function apiFetch(endpoint, options = {}) {
    async function refreshTokenAndRetry(originalEndpoint, originalOptions) {
        try {
            const currentTokens = loadTokens();
            const body = currentTokens.refreshToken ? { refreshToken: currentTokens.refreshToken } : {};
            const rr = await fetch(`${API_BASE_URL}/authenticate/refresh`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });

            if (!rr.ok) throw new Error('Session expired.');

            const newTokens = await rr.json();
            if (newTokens.token) {
                saveTokens(newTokens.token, newTokens.refreshToken || currentTokens.refreshToken);
                // Clone original options and update headers
                const newOptions = { ...originalOptions, headers: { ...(originalOptions.headers || {}), 'Authorization': `Bearer ${newTokens.token}` }};
                // Retry the original request
                return await fetch(`${API_BASE_URL}${originalEndpoint}`, newOptions);
            }
            throw new Error('Failed to refresh session.');
        } catch (e) {
            clearTokens();
            showAlert('Your session has expired. Please sign in again.', 'warning');
            // Redirect to login or let the caller handle it
            window.location.href = '/';
            return Promise.reject('Session expired');
        }
    }

    const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
    const currentTokens = loadTokens();
    if (currentTokens.token) {
        headers['Authorization'] = `Bearer ${currentTokens.token}`;
    }

    const fetchOptions = { ...options, headers, body: options.body ? JSON.stringify(options.body) : null };
    const response = await fetch(`${API_BASE_URL}${endpoint}`, fetchOptions);

    if (response.status === 401) {
        return await refreshTokenAndRetry(endpoint, fetchOptions);
    }

    return response;
}