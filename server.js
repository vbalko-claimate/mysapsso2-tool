const express = require('express');
const path = require('path');
const { decode, encode } = require('./lib/mysapsso2');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Health check
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok' });
});

// Decode endpoint
app.post('/api/decode', (req, res) => {
  try {
    const { token } = req.body;
    if (!token || typeof token !== 'string') {
      return res.status(400).json({ error: 'Missing or invalid "token" field' });
    }
    const result = decode(token);
    res.json(result);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Encode endpoint
app.post('/api/encode', (req, res) => {
  try {
    const { user, sysId, client, validity, pemKey, pemCert } = req.body;
    if (!user) {
      return res.status(400).json({ error: 'Missing "user" field' });
    }
    const token = encode({ user, sysId, client, validity, pemKey, pemCert });
    res.json({ token });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.listen(PORT, () => {
  console.log(`MYSAPSSO2 app listening on http://localhost:${PORT}`);
});
