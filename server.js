require('dotenv').config();

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

const SESSION_SECRET = process.env.SESSION_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true';

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error('FATAL: Set SESSION_SECRET in .env (minimum 32 characters).');
  process.exit(1);
}

if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 8) {
  console.error('FATAL: Set ADMIN_PASSWORD in .env (minimum 8 characters).');
  process.exit(1);
}

let passwordHashPromise = bcrypt.hash(ADMIN_PASSWORD, 12);

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

app.use(
  session({
    name: 'sid',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: 'strict',
      maxAge: 30 * 60 * 1000,
    },
  })
);

function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    const sessionData = {
      csrfToken: req.session.csrfToken,
    };

    req.session.regenerate((err) => {
      if (err) {
        reject(err);
        return;
      }

      req.session.csrfToken = sessionData.csrfToken;
      resolve();
    });
  });
}

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
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  next();
}

function validateCsrf(req, res, next) {
  const token = req.body._csrf || req.headers['x-csrf-token'];

  if (!token || !req.session.csrfToken || token !== req.session.csrfToken) {
    res.status(403).json({ error: 'Invalid or missing CSRF token.' });
    return;
  }

  next();
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

  try {
    await regenerateSession(req);
    req.session.authenticated = true;
    req.session.user = ADMIN_USERNAME;
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');

    req.session.save((err) => {
      if (err) {
        res.status(500).json({ error: 'Unable to create session.' });
        return;
      }
      res.json({ success: true, redirect: '/home' });
    });
  } catch {
    res.status(500).json({ error: 'Unable to create session.' });
  }
});

app.post('/api/logout', requireAuth, validateCsrf, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      res.status(500).json({ error: 'Unable to log out.' });
      return;
    }
    res.clearCookie('sid');
    res.json({ success: true, redirect: '/login' });
  });
});

app.get('/home', requireAuth, (req, res) => {
  res.type('html').send(homeTemplate.replace('{{USER}}', escapeHtml(req.session.user)));
});

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

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

app.listen(PORT, () => {
  console.log(`Secure login running at http://localhost:${PORT}`);
});
