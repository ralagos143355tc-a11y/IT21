# Security Testing Notes

**Authorized use only.** These notes are for testing **your own** deployment of this project (local dev or staging). Do not use them against systems you do not own or have explicit permission to test.

This document describes common attack ideas, whether they work against this app, and why.

---

## What This System Protects Against

Before trying bypasses, understand what is already mitigated in `server.js`:

| Attack | Status | Why |
|--------|--------|-----|
| Brute-force password guessing | Partially blocked | 5 failed attempts per IP per 2 minutes |
| CSRF on login/logout | Blocked | Token required in body or `X-CSRF-Token` header |
| Session fixation | Mitigated | Session ID is regenerated after successful login |
| Password stored in plaintext | Blocked | Password compared via bcrypt hash |
| XSS in welcome message | Mitigated | Username is HTML-escaped on `/home` |
| Clickjacking | Mitigated | Helmet sets security headers |
| Direct static file access without login | Blocked | `/assets/*` runs through `redirectIfAuthenticated` |

---

## Hint 1: Default Credentials

**Easiest “bypass” if `.env` was never changed.**

The app reads credentials from environment variables. If the deployer copied `.env.example` and never updated it:

- Username: `admin`
- Password: `ChangeMeToAStrongPassword123!`

**Lesson:** Change defaults before any shared or production use. This is misconfiguration, not a code flaw.

---

## Hint 2: You Cannot Skip the Server

Opening `public/login.html` directly (`file://` or a static host) will **not** work.

The login form calls:

- `GET /api/csrf-token`
- `POST /api/login`

Those routes exist only on the Express server. Without a valid session and CSRF token from the server, login fails.

**Lesson:** Authentication logic must stay server-side. Client-only pages are not a security boundary.

---

## Hint 3: Guessing the CSRF Token Won't Work

CSRF tokens are 32 random bytes (64 hex characters) stored in the session:

```js
crypto.randomBytes(32).toString('hex')
```

You cannot forge a valid token without access to the session cookie **and** the server accepting your session.

**Try it:** POST to `/api/login` without first calling `/api/csrf-token` with the same session cookie. Expect `403 Invalid or missing CSRF token`.

---

## Hint 4: Rate Limiting Is IP-Based

Login is limited to **5 attempts per 2 minutes per IP address**.

**What works (in theory):**
- Rotating source IPs (many machines, VPN hops, botnet) — impractical for local testing

**What does not work:**
- Rapid password guessing from one IP after the limit is hit

**Try it:** Fail login 6 times quickly from the same machine. The 6th response should be rate-limited.

**Lesson:** Rate limits slow attacks but are not a substitute for strong passwords.

---

## Hint 5: Session Cookie Theft (The Real Session Bypass)

There is no magic URL to “skip login.” The practical bypass path is **stealing a valid session cookie** (`sid`).

The cookie is:

- `httpOnly` — not readable from JavaScript (blocks simple `document.cookie` theft)
- `sameSite: strict` — browser won't send it on cross-site requests
- `secure: false` by default — **sent over plain HTTP**

**When this matters:**

If `COOKIE_SECURE=false` (default for local dev) and traffic goes over **unencrypted HTTP**, anyone on the same network who can sniff packets could capture the `sid` cookie and replay it.

**Try it (locally, ethically):**
1. Log in normally in Browser A
2. Copy the `sid` cookie from DevTools → Application → Cookies
3. Paste it into Browser B (or curl with `-H "Cookie: sid=..."`)
4. Visit `/home` — you are authenticated without knowing the password

**Fix:** Use HTTPS in production and set `COOKIE_SECURE=true` in `.env`.

---

## Hint 6: Weak or Leaked Secrets

### `SESSION_SECRET`

If `SESSION_SECRET` is short, guessable, or committed to git, an attacker who obtains it may be able to forge session cookies (depending on session store and library behavior).

**Check:** Is your secret at least 32 random characters? Is `.env` in `.gitignore` and never pushed?

### `.env` file exposure

If the server or hosting misconfiguration exposes `.env` (directory listing, backup file, public repo), the attacker gets:

- `ADMIN_USERNAME`
- `ADMIN_PASSWORD` (plaintext in env)
- `SESSION_SECRET`

That is full compromise — not a clever bypass.

**Try it:** Confirm `.env` is not served by Express (it should not be under `public/`).

---

## Hint 7: Timing Side Channels

Failed login adds a random delay of 500–1000 ms before responding. This reduces the usefulness of timing attacks that compare “user not found” vs “wrong password.”

**What does not work well:**
- Measuring response time to enumerate valid usernames (only one user exists anyway)

---

## Hint 8: SQL Injection / NoSQL Injection

**Not applicable.** This app has no database. Credentials are compared against environment variables in memory.

Do not waste time on `' OR 1=1 --` style payloads here.

---

## Hint 9: Path Traversal on Login Page

**Unlikely.** `/login` serves a fixed file:

```js
res.sendFile(path.join(__dirname, 'public', 'login.html'));
```

There is no user-controlled path segment.

---

## Hint 10: Logout CSRF

Logout requires authentication **and** a valid CSRF token. An attacker cannot log you out via a simple `<img src="/api/logout">` from another site (wrong method, no CSRF token, cookie not sent cross-site with `SameSite=strict`).

---

## Suggested Test Checklist

Use this when hardening your deployment:

- [ ] Changed `ADMIN_PASSWORD` from the example value
- [ ] `SESSION_SECRET` is 32+ cryptographically random characters
- [ ] `.env` is not in git and not web-accessible
- [ ] `COOKIE_SECURE=true` when using HTTPS
- [ ] Rate limit triggers after 5 bad logins from one IP
- [ ] `/home` returns 302 to `/login` when no session cookie is sent
- [ ] `/api/login` without CSRF token returns 403
- [ ] Static assets under `/assets/` redirect to login when unauthenticated
- [ ] Session cookie is not accessible via `document.cookie` in the browser console

---

## What Would Require Major Architecture Changes to Defend

This is a **single-user, env-based** login demo. It does **not** include:

- Multi-user accounts or password reset
- Multi-factor authentication (MFA)
- Account lockout beyond IP rate limiting
- Persistent session store (Redis/DB) for server clusters
- Audit logging
- CAPTCHA after failed attempts
- IP allowlists

Those gaps are design scope limits, not “hidden bypass buttons.”

---

## Summary

| Goal | Realistic approach on this app |
|------|--------------------------------|
| Log in without password | Default/leaked credentials, stolen `sid` cookie, or leaked `.env` |
| Forge session without credentials | Weak/leaked `SESSION_SECRET` (misconfiguration) |
| Brute force password | Slowed by rate limit; still possible with weak password + many IPs |
| Skip CSRF | Does not work with normal HTTP client behavior |
| Access `/home` with no session | Does not work — redirects to `/login` |

The strongest practical bypasses are **misconfiguration** (default password, exposed secrets) and **session hijacking on HTTP** — not tricks in the HTML or JavaScript alone.

---

## Responsible Disclosure

If you extend this project and find a new vulnerability, document it, fix it in code, and add a test case. Do not publish working exploit chains against production systems without permission.
