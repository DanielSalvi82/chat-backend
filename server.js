require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const http = require('http');
const WebSocket = require('ws');

const SHARED_SECRET = process.env.SHARED_SECRET;
const PORT = process.env.PORT || 3000;
const PROCESSING_TIMEOUT_MS = 5 * 60 * 1000;

if (!SHARED_SECRET) { console.error('Missing SHARED_SECRET'); process.exit(1); }

const app = express();
app.use(bodyParser.json({ limit: '2mb' }));

const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

const jobs = new Map();
const connectionsByRequest = new Map();
const clientsMeta = new Map();

function computeHmacHex(payload, secret) {
  return crypto.createHmac('sha256', secret).update(payload, 'utf8').digest('hex');
}

function broadcastToRequest(request_id, payload) {
  const set = connectionsByRequest.get(request_id);
  const msg = JSON.stringify(payload);
  if (set && set.size > 0) {
    for (const ws of set) if (ws.readyState === WebSocket.OPEN) ws.send(msg);
  } else {
    wss.clients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(msg); });
  }
}

function terminateClientsForRequest(request_id) {
  const set = connectionsByRequest.get(request_id);
  if (!set) return;
  for (const ws of set) { try { ws.terminate(); } catch(e){} }
  connectionsByRequest.delete(request_id);
}

wss.on('connection', (ws) => {
  clientsMeta.set(ws, { userId: null, requestIds: new Set() });
  ws.send(JSON.stringify({ type: 'welcome', message: 'connected' }));

  ws.on('message', (msg) => {
    try {
      const payload = JSON.parse(msg);
      if (payload.type === 'identify' && payload.user_id) {
        const meta = clientsMeta.get(ws) || {};
        meta.userId = payload.user_id;
        clientsMeta.set(ws, meta);
      } else if (payload.type === 'subscribe' && payload.request_id) {
        const set = connectionsByRequest.get(payload.request_id) || new Set();
        set.add(ws);
        connectionsByRequest.set(payload.request_id, set);
        const meta = clientsMeta.get(ws) || { userId: null, requestIds: new Set() };
        meta.requestIds.add(payload.request_id);
        clientsMeta.set(ws, meta);
      }
    } catch (e) {}
  });

  ws.on('close', () => {
    const meta = clientsMeta.get(ws);
    if (meta && meta.requestIds) {
      for (const rid of meta.requestIds) {
        const set = connectionsByRequest.get(rid);
        if (set) { set.delete(ws); if (set.size === 0) connectionsByRequest.delete(rid); }
      }
    }
    clientsMeta.delete(ws);
  });
});

app.get('/status', (req, res) => {
  const request_id = req.query.request_id;
  if (!request_id) return res.status(400).json({ error: 'missing request_id' });
  const rec = jobs.get(request_id);
  if (!rec) return res.status(404).json({ error: 'not found' });
  return res.json(rec);
});

app.post('/callbacks/fireworks', async (req, res) => {
  try {
    const rawBody = JSON.stringify(req.body || {});
    const signatureHeader = req.get('X-Signature') || '';
    if (signatureHeader) {
      const parts = signatureHeader.split('=');
      if (parts.length !== 2 || parts[0] !== 'sha256') return res.status(401).json({ error: 'invalid signature format' });
      const sigHex = parts[1];
      const computed = computeHmacHex(rawBody, SHARED_SECRET);
      if (!crypto.timingSafeEqual(Buffer.from(sigHex, 'hex'), Buffer.from(computed, 'hex'))) return res.status(401).json({ error: 'invalid signature' });
    } else {
      if (!req.body.shared_secret || req.body.shared_secret !== SHARED_SECRET) return res.status(401).json({ error: 'invalid shared_secret' });
    }

    const { request_id, status, response: resp, analysis, error } = req.body || {};
    if (!request_id) return res.status(400).json({ error: 'missing request_id' });

    const existing = jobs.get(request_id);
    if (existing && (existing.status === 'completed' || existing.status === 'timed_out')) return res.status(200).json({ ok: true, note: 'already processed' });

    const now = new Date().toISOString();
    const record = { request_id, status: status || 'processing', response: resp || '', analysis: analysis || '', error: error || '', updatedAt: now };
    jobs.set(request_id, record);

    const timeoutId = setTimeout(() => {
      const rec = jobs.get(request_id);
      if (!rec) return;
      if (rec.status !== 'completed') {
        rec.status = 'timed_out';
        rec.updatedAt = new Date().toISOString();
        jobs.set(request_id, rec);
        broadcastToRequest(request_id, { type: 'job_timeout', request_id, message: 'Processamento excedeu 5 minutos' });
        terminateClientsForRequest(request_id);
      }
    }, PROCESSING_TIMEOUT_MS);

    record._timeoutId = timeoutId;
    jobs.set(request_id, record);

    // Aqui tratamos o payload como resultado final (ajuste se precisar processar)
    clearTimeout(timeoutId);
    record.status = 'completed';
    record.response = resp || record.response || '';
    record.updatedAt = new Date().toISOString();
    delete record._timeoutId;
    jobs.set(request_id, record);

    broadcastToRequest(request_id, { type: 'job_completed', request_id, status: record.status, response: record.response, response_markdown: true });

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('callback error', err);
    return res.status(500).json({ error: 'internal error' });
  }
});

server.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
