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

const SESSION_SECRET = process.env.SESSION_SECRET || '';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const COOKIE_SECURE =
  process.env.COOKIE_SECURE === 'true' ||
  (IS_VERCEL && process.env.COOKIE_SECURE !== 'false');

const configOk = SESSION_SECRET.length >= 32 && ADMIN_PASSWORD.length >= 8;

function readPublic(fileName) {
  const filePath = path.join(__dirname, 'public', fileName);
  return fs.readFileSync(filePath, 'utf8');
}

function sendPublicFile(res, fileName) {
  const filePath = path.join(__dirname, 'public', fileName);
  res.sendFile(filePath);
}

function configErrorPage(res) {
  res.status(500).type('html').send(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Config error</title></head>
<body style="font-family:system-ui;max-width:40rem;margin:3rem auto;padding:0 1rem;line-height:1.5">
  <h1>Server configuration error</h1>
  <p>Required environment variables are missing or too short.</p>
  <ul>
    <li><code>SESSION_SECRET</code> must be at least <strong>32</strong> characters (current length: ${SESSION_SECRET.length})</li>
    <li><code>ADMIN_PASSWORD</code> must be at least <strong>8</strong> characters (current length: ${ADMIN_PASSWORD.length})</li>
  </ul>
  <p>After changing variables in Vercel, you must <strong>Redeploy</strong> for them to apply.</p>
</body></html>`);
}

app.set('trust proxy', 1);

app.get('/health', (req, res) => {
  res.json({
    ok: true,
    vercel: IS_VERCEL,
    configOk,
    sessionSecretLength: SESSION_SECRET.length,
    adminPasswordLength: ADMIN_PASSWORD.length,
  });
});

app.use((req, res, next) => {
  if (!configOk) {
    configErrorPage(res);
    return;
  }
  next();
});

if (configOk) {
  const passwordHashPromise = bcrypt.hash(ADMIN_PASSWORD, 12);
  let homeTemplate = '';
  try {
    homeTemplate = readPublic('home.html');
  } catch (err) {
    console.error('home.html not found in bundle:', err.message);
  }

  const loginLimiter = rateLimit({
    windowMs: 2 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many login attempts. Try again in 2 minutes.' },
    skipSuccessfulRequests: true,
  });

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
    try {
      sendPublicFile(res, 'login.html');
    } catch (err) {
      res.status(500).send('login.html missing from deployment bundle: ' + err.message);
    }
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
    if (!homeTemplate) {
      res.status(500).send('home.html missing from deployment bundle. Check vercel.json includeFiles.');
      return;
    }
    res.type('html').send(homeTemplate.replace('{{USER}}', escapeHtml(req.session.user)));
  });

  app.use('/css', express.static(path.join(__dirname, 'public', 'css')));
  app.use('/js', express.static(path.join(__dirname, 'public', 'js')));

  app.get('/', (req, res) => {
    if (req.session && req.session.authenticated) {
      res.redirect('/home');
      return;
    }
    res.redirect('/login');
  });
}

app.use((req, res) => {
  if (!configOk) {
    configErrorPage(res);
    return;
  }
  res.status(404).send('Not found');
});

module.exports = app;

if (require.main === module) {
  if (!configOk) {
    console.error('FATAL: Set SESSION_SECRET (min 32 chars) and ADMIN_PASSWORD (min 8 chars).');
    process.exit(1);
  }
  app.listen(PORT, () => {
    console.log(`Secure login running at http://localhost:${PORT}`);
  });
}
