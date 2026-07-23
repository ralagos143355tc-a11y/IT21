require('dotenv').config();

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const express = require('express');
const cookieSession = require('cookie-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const IS_VERCEL = Boolean(process.env.VERCEL);

const SESSION_SECRET = process.env.SESSION_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const COOKIE_SECURE =
  process.env.COOKIE_SECURE === 'true' ||
  (IS_VERCEL && process.env.COOKIE_SECURE !== 'false');

function configErrorPage(res) {
  res.status(500).type('html').send(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Config error</title></head>
<body style="font-family:system-ui;max-width:40rem;margin:3rem auto;padding:0 1rem;line-height:1.5">
  <h1>Server configuration error</h1>
  <p>Required environment variables are missing on this host.</p>
  <p>In the Vercel dashboard go to <strong>Settings → Environment Variables</strong> and add:</p>
  <ul>
    <li><code>SESSION_SECRET</code> — at least 32 random characters</li>
    <li><code>ADMIN_PASSWORD</code> — at least 8 characters</li>
    <li><code>ADMIN_USERNAME</code> — optional (default <code>admin</code>)</li>
  </ul>
  <p>Then redeploy the project.</p>
</body></html>`);
}

if (!SESSION_SECRET || SESSION_SECRET.length < 32 || !ADMIN_PASSWORD || ADMIN_PASSWORD.length < 8) {
  console.error('FATAL: Set SESSION_SECRET (min 32 chars) and ADMIN_PASSWORD (min 8 chars).');
  if (!IS_VERCEL) {
    process.exit(1);
  }
  app.use((req, res) => configErrorPage(res));
  module.exports = app;
} else {
  const passwordHashPromise = bcrypt.hash(ADMIN_PASSWORD, 12);
  const homeTemplate = fs.readFileSync(path.join(__dirname, 'public', 'home.html'), 'utf8');

  const loginLimiter = rateLimit({
    windowMs: 2 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many login attempts. Try again in 2 minutes.' },
    skipSuccessfulRequests: true,
  });

  app.set('trust proxy', 1);

  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "https://fonts.googleapis.com"],
          fontSrc: ["'self'", "https://fonts.gstatic.com"],
          imgSrc: ["'self'"],
          connectSrc: ["'self'"],
          frameSrc: ["'none'"],
          objectSrc: ["'none'"],
          baseUri: ["'self'"],
          formAction: ["'self'"],
        },
      },
    })
  );

  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));

  // Cookie-backed sessions work on Vercel serverless (no in-memory store).
  app.use(
    cookieSession({
      name: 'sid',
      keys: [SESSION_SECRET],
      maxAge: 30 * 60 * 1000,
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: 'lax',
    })
  );

  function requireAuth(req, res, next) {
    if (req.session && req.session.authenticated === true && req.session.user) {
      next();
      return;
    }

    if (req.accepts('json') && !req.accepts('html')) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }

    res.redirect('/login');
  }

  function redirectIfAuthenticated(req, res, next) {
    if (req.session && req.session.authenticated === true) {
      res.redirect('/home');
      return;
    }
    next();
  }

  function ensureCsrfToken(req, res, next) {
    if (!req.session) {
      req.session = {};
    }
    if (!req.session.csrfToken) {
      req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    next();
  }

  function validateCsrf(req, res, next) {
    const token = req.body._csrf || req.headers['x-csrf-token'];

    if (!token || !req.session || !req.session.csrfToken || token !== req.session.csrfToken) {
      res.status(403).json({ error: 'Invalid or missing CSRF token.' });
      return;
    }

    next();
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  app.get('/login', redirectIfAuthenticated, ensureCsrfToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
  });

  app.get('/api/csrf-token', ensureCsrfToken, (req, res) => {
    res.json({ csrfToken: req.session.csrfToken });
  });

  app.post('/api/login', loginLimiter, ensureCsrfToken, validateCsrf, async (req, res) => {
    const username = typeof req.body.username === 'string' ? req.body.username.trim() : '';
    const password = typeof req.body.password === 'string' ? req.body.password : '';

    if (!username || !password) {
      res.status(400).json({ error: 'Invalid credentials.' });
      return;
    }

    const passwordHash = await passwordHashPromise;
    const usernameMatch = username === ADMIN_USERNAME;
    const passwordMatch = await bcrypt.compare(password, passwordHash);

    if (!usernameMatch || !passwordMatch) {
      await new Promise((resolve) => setTimeout(resolve, 500 + Math.random() * 500));
      res.status(401).json({ error: 'Invalid credentials.' });
      return;
    }

    req.session = {
      authenticated: true,
      user: ADMIN_USERNAME,
      csrfToken: crypto.randomBytes(32).toString('hex'),
    };

    res.json({ success: true, redirect: '/home' });
  });

  app.post('/api/logout', requireAuth, validateCsrf, (req, res) => {
    req.session = null;
    res.clearCookie('sid');
    res.json({ success: true, redirect: '/login' });
  });

  app.get('/home', requireAuth, (req, res) => {
    res.type('html').send(homeTemplate.replace('{{USER}}', escapeHtml(req.session.user)));
  });

  app.use('/css', express.static(path.join(__dirname, 'public', 'css')));
  app.use('/js', express.static(path.join(__dirname, 'public', 'js')));
  app.use('/assets', express.static(path.join(__dirname, 'public')));

  app.get('/', (req, res) => {
    if (req.session && req.session.authenticated) {
      res.redirect('/home');
      return;
    }
    res.redirect('/login');
  });

  app.use((req, res) => {
    res.status(404).send('Not found');
  });

  module.exports = app;

  if (require.main === module) {
    app.listen(PORT, () => {
      console.log(`Secure login running at http://localhost:${PORT}`);
    });
  }
}
