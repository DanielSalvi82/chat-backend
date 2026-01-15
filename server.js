// server.js
const path = require('path');
const express = require('express');

const app = express();

// servir arquivos estáticos da pasta "public"
app.use(express.static(path.join(__dirname, 'public')));

// rota raiz: serve public/index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// rota de status mínima (útil para health checks)
app.get('/status', (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
