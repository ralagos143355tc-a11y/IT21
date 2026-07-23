# Secure Login System

A Node.js and Express web application with server-side session authentication, CSRF protection, and a simple sign-in UI. Credentials are stored in environment variables and verified with bcrypt.

## Features

- Username and password authentication via environment configuration
- Server-side sessions with HTTP-only cookies
- CSRF tokens on login and logout
- Rate limiting on login attempts (5 tries per 2 minutes)
- Security headers via Helmet (including Content Security Policy)
- Cookie-backed sessions (works on Vercel serverless)
- Protected routes and static assets for unauthenticated users

## Requirements

- [Node.js](https://nodejs.org/) 18 or later
- npm

## Quick Start

1. **Install dependencies**

   ```bash
   npm install
   ```

2. **Create your environment file**

   ```bash
   copy .env.example .env
   ```

   On macOS/Linux:

   ```bash
   cp .env.example .env
   ```

3. **Edit `.env`** and set a strong `SESSION_SECRET` (at least 32 characters) and `ADMIN_PASSWORD` (at least 8 characters).

4. **Start the server**

   ```bash
   npm start
   ```

5. **Open the app** at [http://localhost:3000](http://localhost:3000)

## Deploy on Vercel

The npm deprecation warnings during install are harmless. The **500 FUNCTION_INVOCATION_FAILED** error happens when required secrets are missing or the app is not set up as a serverless function.

1. Push this repo to GitHub (already connected if you linked it).
2. In Vercel → **Project → Settings → Environment Variables**, add:

| Name | Value | Notes |
|------|--------|--------|
| `SESSION_SECRET` | long random string (32+ chars) | Required |
| `ADMIN_PASSWORD` | your password (8+ chars) | Required |
| `ADMIN_USERNAME` | `admin` | Optional |

3. Redeploy (Deployments → … → Redeploy), or push a new commit.
4. Open your `*.vercel.app` URL and sign in with those credentials.

`COOKIE_SECURE` defaults to on for Vercel (HTTPS). Local `npm start` still uses your `.env` file.

## Default Credentials

After copying `.env.example`, the default login is:

| Field      | Value                        |
|------------|------------------------------|
| Username   | `admin`                      |
| Password   | `ChangeMeToAStrongPassword123!` |

Change these in `.env` before deploying to production.

## Configuration

| Variable         | Required | Default | Description                                      |
|------------------|----------|---------|--------------------------------------------------|
| `SESSION_SECRET` | Yes      | —       | Secret for signing session cookies (min 32 chars) |
| `ADMIN_USERNAME` | No       | `admin` | Login username                                   |
| `ADMIN_PASSWORD` | Yes      | —       | Login password (min 8 chars)                     |
| `COOKIE_SECURE`  | No       | `false` | Set to `true` when serving over HTTPS            |
| `PORT`           | No       | `3000`  | Port the server listens on                       |

## Running with VS Code

The project includes debug configuration that starts the server and opens Chrome:

1. Press **F5** or use **Run → Start Debugging**
2. Select **Launch Chrome against localhost**

This runs `npm start` and opens [http://localhost:3000](http://localhost:3000).

## Project Structure

```
System/
├── server.js              # Express server, auth logic, and routes
├── public/
│   ├── login.html         # Sign-in page
│   ├── css/login.css      # Styles
│   └── js/
│       ├── login.js       # Login form and API calls
│       └── logout.js      # Sign-out handler
├── .env.example           # Environment template
├── .vscode/
│   ├── launch.json        # Chrome debug configuration
│   └── tasks.json         # Pre-launch server task
└── package.json
```

## Routes

| Method | Path              | Auth     | Description                    |
|--------|-------------------|----------|--------------------------------|
| GET    | `/`               | —        | Redirects to `/home` or `/login` |
| GET    | `/login`          | —        | Sign-in page                   |
| GET    | `/home`           | Required | Authenticated welcome page     |
| GET    | `/api/csrf-token` | —        | Returns CSRF token for forms   |
| POST   | `/api/login`      | —        | Authenticates user             |
| POST   | `/api/logout`     | Required | Ends session                   |
| GET    | `/assets/*`       | Required | Static CSS and JS              |

## Security Notes

- Do not open `login.html` directly in the browser. The login flow requires the running server for CSRF tokens and API endpoints.
- Never commit `.env` to version control. It is listed in `.gitignore`.
- Set `COOKIE_SECURE=true` in production when using HTTPS.
- Replace the default username and password before going live.
- Failed login responses include a short random delay to reduce timing attacks.

## Scripts

| Command       | Description        |
|---------------|--------------------|
| `npm start`   | Start the server   |
| `npm run dev` | Same as `npm start` |

## License

Private project — all rights reserved.
