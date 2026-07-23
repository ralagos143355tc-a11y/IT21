// Local development entry. Vercel uses api/index.js instead.
const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

app.get('/', (req, res) => {
  res.send('Use npm start locally. Production is served via api/index.js on Vercel.');
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`http://localhost:${PORT}`));
}

module.exports = app;
