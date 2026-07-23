try {
  module.exports = require('../server');
} catch (error) {
  console.error('Boot failure:', error);
  module.exports = (req, res) => {
    res.statusCode = 500;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.end(
      'Boot failure: ' +
        (error && error.stack ? error.stack : String(error)) +
        '\n\nCheck that SESSION_SECRET is 32+ chars, ADMIN_PASSWORD is 8+ chars, and you Redeployed after setting env vars.'
    );
  };
}
