async function logout() {
  const btn = document.getElementById('logout-btn');
  btn.disabled = true;

  try {
    const csrfResponse = await fetch('/api/csrf-token', { credentials: 'same-origin' });
    if (!csrfResponse.ok) {
      window.location.href = '/login';
      return;
    }

    const { csrfToken } = await csrfResponse.json();

    const response = await fetch('/api/logout', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
      },
      body: JSON.stringify({ _csrf: csrfToken }),
    });

    if (response.ok) {
      window.location.href = '/login';
      return;
    }
  } catch {
    // Network or server error — re-enable button so user can retry.
  }

  btn.disabled = false;
}

document.getElementById('logout-btn').addEventListener('click', logout);
