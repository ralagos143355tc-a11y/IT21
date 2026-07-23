# How to Bypass This System (Lab Guide)

**Authorized use only.** Use these steps only against **your own** local IT21 deployment (`localhost`). Do not use them against systems you do not own or have permission to test.

This app has no “magic URL” that skips login. The realistic bypass paths are **misconfiguration** and **session cookie replay**.

---

## Prerequisites

1. Server running:

   ```bash
   npm start
   ```

2. App open at [http://localhost:3000](http://localhost:3000)

3. Optional tools:
   - Browser DevTools
   - [Burp Suite](https://portswigger.net/burp) (Community is fine)
   - `curl` (built into Kali / Git Bash / macOS / modern Windows)

---

## Bypass 1: Default Credentials (Misconfiguration)

If `.env` was copied from `.env.example` and never changed:

| Field    | Default value                      |
|----------|------------------------------------|
| Username | `admin`                            |
| Password | `ChangeMeToAStrongPassword123!`    |

**Steps**

1. Open `/login`
2. Enter the defaults above
3. Click **Sign in**

**Why it works:** Credentials come from environment variables. Unchanged defaults are not a code bug — they are a deployment mistake.

**Fix:** Set a strong unique `ADMIN_PASSWORD` (and `SESSION_SECRET`) in `.env` before sharing or deploying.

---

## Bypass 2: Session Cookie Replay (Main Lab Attack)

After a victim (or you) logs in once, anyone who obtains the `sid` cookie can open `/home` **without knowing the password**.

### Cookie properties in this app

| Property   | Value                         | Effect                                      |
|------------|-------------------------------|---------------------------------------------|
| Name       | `sid`                         | Session identifier                          |
| `httpOnly` | `true`                        | Not readable via `document.cookie`          |
| `sameSite` | `strict`                      | Not sent on cross-site requests             |
| `secure`   | `false` by default            | Cookie is sent over plain HTTP              |
| Lifetime   | 30 minutes                    | Replay works until expiry or logout         |

### Method A — Browser DevTools

1. Log in normally in **Browser A**
2. Open DevTools → **Application** → **Cookies** → `http://localhost:3000`
3. Copy the value of `sid`
4. In **Browser B** (or a private window), open DevTools → Cookies
5. Add a cookie:
   - Name: `sid`
   - Value: *(paste)*
   - Domain: `localhost`
6. Visit [http://localhost:3000/home](http://localhost:3000/home)

You should see the dashboard without signing in.

### Method B — curl

```bash
curl -i http://localhost:3000/home -H "Cookie: sid=PASTE_SID_HERE"
```

A successful replay returns the dashboard HTML. Without a valid cookie you get redirected to `/login`.

### Method C — Burp Suite (as on the login hint)

1. Configure the browser proxy to Burp (`127.0.0.1:8080`)
2. Browse to `/login` and sign in
3. In Burp **HTTP history**, find `POST /api/login` or a later request to `/home`
4. Copy the `sid` value from the `Set-Cookie` / `Cookie` header
5. Replay with curl:

   ```bash
   curl -i http://localhost:3000/home -H "Cookie: sid=PASTE_SID_HERE"
   ```

**Why it works:** Authentication is “whoever presents a valid server session.” Stealing/replaying `sid` is enough.

**Fix for real deployments:** Use HTTPS and set `COOKIE_SECURE=true` in `.env`. Never share session cookies.

---

## Bypass 3: Exposed `.env` / Weak Secrets

If `.env` leaks (public repo, backup file, misconfigured host), an attacker gets:

- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `SESSION_SECRET`

That is full compromise — log in directly, or potentially abuse a weak/leaked session secret.

**Check**

```bash
# .env must NOT be under public/ and must be in .gitignore
```

**Fix:** Keep `.env` private; use a long random `SESSION_SECRET` (32+ characters).

---

## What Does Not Bypass This System

| Attempt                         | Result                                      |
|---------------------------------|---------------------------------------------|
| Open `login.html` as a file     | No CSRF/API — login fails                   |
| POST login without CSRF token   | `403 Invalid or missing CSRF token`         |
| Guess CSRF token                | Practically impossible (64 hex chars)       |
| Brute force after 5 failures    | Rate limited for **2 minutes** per IP       |
| SQL / NoSQL injection           | No database                                 |
| Read `sid` via JavaScript       | Blocked by `httpOnly`                       |
| Simple cross-site logout/login  | Blocked by CSRF + `SameSite=strict`         |
| Visit `/home` with no cookie    | Redirect to `/login`                        |

---

## Quick Lab Checklist

- [ ] Default password still works if `.env` was not changed
- [ ] Copy `sid` from DevTools → open `/home` in another browser
- [ ] `curl` with `Cookie: sid=...` returns dashboard HTML
- [ ] `curl` without cookie redirects to login
- [ ] Six rapid failed logins triggers the 2-minute rate limit
- [ ] Login without CSRF returns 403

---

## Summary

| Goal                         | Realistic path on this app              |
|------------------------------|-----------------------------------------|
| Enter without changing code  | Default/leaked credentials              |
| Access `/home` after a login | Replay stolen `sid` cookie              |
| Full compromise              | Leaked `.env` or weak secrets           |
| Skip CSRF / forge session    | Does not work under normal conditions   |

For deeper attack/defense notes, see [SECURITY-TESTING.md](./SECURITY-TESTING.md).
