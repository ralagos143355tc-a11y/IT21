module.exports = (req, res) => {
  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json');
  res.end(
    JSON.stringify({
      ok: true,
      url: req.url,
      hasSessionSecret: Boolean(process.env.SESSION_SECRET),
      sessionSecretLength: (process.env.SESSION_SECRET || '').length,
      hasAdminPassword: Boolean(process.env.ADMIN_PASSWORD),
      adminPasswordLength: (process.env.ADMIN_PASSWORD || '').length,
    })
  );
};
