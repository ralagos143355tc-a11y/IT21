const express = require('express');
const app = express();

app.get('/health', (req, res) => {
  res.json({
    ok: true,
    hasSessionSecret: Boolean(process.env.SESSION_SECRET),
    sessionSecretLength: (process.env.SESSION_SECRET || '').length,
    hasAdminPassword: Boolean(process.env.ADMIN_PASSWORD),
    adminPasswordLength: (process.env.ADMIN_PASSWORD || '').length,
    hasAdminUsername: Boolean(process.env.ADMIN_USERNAME),
    vercel: Boolean(process.env.VERCEL),
  });
});

app.get('/', (req, res) => {
  res.type('html').send('<h1>IT21 is running on Vercel</h1><p><a href="/health">/health</a></p>');
});

module.exports = app;
