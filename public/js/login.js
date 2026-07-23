async function fetchCsrfToken() {
  const response = await fetch('/api/csrf-token', {
    credentials: 'same-origin',
  });

  if (!response.ok) {
    throw new Error('Unable to initialize login.');
  }

  const data = await response.json();
  return data.csrfToken;
}

function showError(message) {
  const errorEl = document.getElementById('error-message');
  errorEl.textContent = message;
  errorEl.hidden = false;
}

function clearError() {
  const errorEl = document.getElementById('error-message');
  errorEl.textContent = '';
  errorEl.hidden = true;
}

async function initLogin() {
  const form = document.getElementById('login-form');
  const csrfInput = document.getElementById('csrf-token');
  const submitBtn = document.getElementById('submit-btn');

  try {
    csrfInput.value = await fetchCsrfToken();
  } catch {
    showError('Unable to load login form. Refresh the page.');
    submitBtn.disabled = true;
    return;
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    clearError();
    submitBtn.disabled = true;

    const username = form.username.value.trim();
    const password = form.password.value;

    if (!username || !password) {
      showError('Username and password are required.');
      submitBtn.disabled = false;
      return;
    }

    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfInput.value,
        },
        body: JSON.stringify({
          username,
          password,
          _csrf: csrfInput.value,
        }),
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        showError(data.error || 'Sign in failed.');
        submitBtn.disabled = false;
        return;
      }

      window.location.href = data.redirect || '/home';
    } catch {
      showError('Network error. Try again.');
      submitBtn.disabled = false;
    }
  });
}

initLogin();
