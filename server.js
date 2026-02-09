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
    if (token.length > 32768) {
      return res.status(400).json({ error: 'Token too large (max 32 KB)' });
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
    if (!user || typeof user !== 'string') {
      return res.status(400).json({ error: 'Missing "user" field' });
    }
    if (user.length > 40) {
      return res.status(400).json({ error: 'User too long (max 40 chars)' });
    }
    if (sysId && (typeof sysId !== 'string' || sysId.length > 3)) {
      return res.status(400).json({ error: 'System ID must be up to 3 characters' });
    }
    if (client && (typeof client !== 'string' || !/^\d{1,3}$/.test(client))) {
      return res.status(400).json({ error: 'Client must be 1-3 digits' });
    }
    if (validity && (typeof validity !== 'string' || !/^\d{14}$/.test(validity))) {
      return res.status(400).json({ error: 'Validity must be 14 digits (YYYYMMDDHHmmss)' });
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
