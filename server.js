// server.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');

const SHARED_SECRET = process.env.SHARED_SECRET;
const PORT = process.env.PORT || 3000;
const TIMEOUT_MS = 5 * 60 * 1000; // 5 minutos

if (!SHARED_SECRET) {
  console.error('Missing SHARED_SECRET in environment');
  process.exit(1);
}

const app = express();
app.use(bodyParser.json({ limit: '2mb' }));

// servir arquivos estáticos da pasta public
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

// In-memory stores
const jobs = new Map(); // request_id -> { status, response, timeoutId, createdAt, updatedAt }
const subs = new Map(); // request_id -> Set(ws)
const meta = new Map(); // ws -> Set(request_id)

function nowISO() { return new Date().toISOString(); }

function computeHmacHex(payload, secret) {
  return crypto.createHmac('sha256', secret).update(payload, 'utf8').digest('hex');
}

function safeSend(ws, obj) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    try { ws.send(JSON.stringify(obj)); } catch (e) { /* ignore */ }
  }
}

function broadcastToRequest(request_id, obj) {
  const set = subs.get(request_id);
  if (set && set.size) {
    for (const ws of set) safeSend(ws, obj);
  } else {
    // fallback: broadcast to all connected clients
    wss.clients.forEach(c => safeSend(c, obj));
  }
}

function scheduleTimeout(request_id) {
  const job = jobs.get(request_id);
  if (!job) return;
  if (job.timeoutId) clearTimeout(job.timeoutId);
  const id = setTimeout(() => {
    const j = jobs.get(request_id);
    if (!j) return;
    if (j.status !== 'completed') {
      j.status = 'timed_out';
      j.updatedAt = nowISO();
      jobs.set(request_id, j);
      broadcastToRequest(request_id, { type: 'job_timeout', request_id, status: j.status, message: 'Timeout 5 minutos' });
      subs.delete(request_id);
      console.warn(`Request ${request_id} timed out`);
    }
  }, TIMEOUT_MS);
  job.timeoutId = id;
  jobs.set(request_id, job);
}

// WebSocket handling
wss.on('connection', (ws) => {
  meta.set(ws, new Set());
  safeSend(ws, { type: 'welcome', message: 'connected' });

  ws.on('message', (msg) => {
    let p;
    try { p = JSON.parse(msg); } catch (e) { return; }
    if (p.type === 'subscribe' && p.request_id) {
      const set = subs.get(p.request_id) || new Set();
      set.add(ws);
      subs.set(p.request_id, set);
      meta.get(ws).add(p.request_id);
      const j = jobs.get(p.request_id);
      if (j) safeSend(ws, { type: 'job_state', request_id: p.request_id, status: j.status, response: j.response || null });
    }
  });

  ws.on('close', () => {
    const s = meta.get(ws);
    if (s) {
      for (const rid of s) {
        const set = subs.get(rid);
        if (set) {
          set.delete(ws);
          if (set.size === 0) subs.delete(rid);
        }
      }
    }
    meta.delete(ws);
  });
});

// Start endpoint: frontend calls this to create request_id (no timeout scheduled here)
app.post('/start', (req, res) => {
  const { payload } = req.body || {};
  const request_id = `r-${Date.now()}-${Math.random().toString(36).slice(2,8)}`;
  const job = { request_id, status: 'pending', response: null, createdAt: nowISO(), updatedAt: nowISO(), timeoutId: null };
  jobs.set(request_id, job);

  const callback_url = `${req.protocol}://${req.get('host')}/callbacks/fireworks`;
  console.log(`Created request ${request_id}`);
  return res.json({ ok: true, request_id, callback_url });
});

// Endpoint to signal that external processing (cenario 2) has started — schedules timeout
app.post('/external-start', (req, res) => {
  const { request_id } = req.body || {};
  if (!request_id) return res.status(400).json({ error: 'missing request_id' });

  const job = jobs.get(request_id);
  if (!job) return res.status(404).json({ error: 'not found' });

  if (job.status === 'completed' || job.status === 'timed_out') {
    return res.status(200).json({ ok: true, note: 'job already finished' });
  }

  job.status = 'processing';
  job.updatedAt = nowISO();
  jobs.set(request_id, job);

  scheduleTimeout(request_id);
  console.log(`External processing started for ${request_id}; timeout scheduled`);
  return res.json({ ok: true, request_id, note: 'external processing started; timeout scheduled' });
});

// Status endpoint
app.get('/status', (req, res) => {
  const request_id = req.query.request_id;
  if (!request_id) return res.status(400).json({ error: 'missing request_id' });
  const j = jobs.get(request_id);
  if (!j) return res.status(404).json({ error: 'not found' });
  return res.json(j);
});

// Callback endpoint for external workflow (Make / GitHub)
app.post('/callbacks/fireworks', (req, res) => {
  try {
    const raw = JSON.stringify(req.body || {});
    const sigHeader = req.get('X-Signature') || '';
    if (sigHeader) {
      const parts = sigHeader.split('=');
      if (parts.length !== 2 || parts[0] !== 'sha256') return res.status(401).json({ error: 'invalid signature format' });
      const sigHex = parts[1];
      const computed = computeHmacHex(raw, SHARED_SECRET);
      const a = Buffer.from(sigHex, 'hex');
      const b = Buffer.from(computed, 'hex');
      if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ error: 'invalid signature' });
    } else {
      if (!req.body.shared_secret || req.body.shared_secret !== SHARED_SECRET) return res.status(401).json({ error: 'invalid shared_secret' });
    }

    const { request_id, status, response } = req.body || {};
    if (!request_id) return res.status(400).json({ error: 'missing request_id' });

    const job = jobs.get(request_id) || { request_id, createdAt: nowISO() };
    if (job.status === 'completed') return res.status(200).json({ ok: true, note: 'already completed' });

    if (job.timeoutId) { clearTimeout(job.timeoutId); job.timeoutId = null; }

    job.status = status || 'completed';
    job.response = response || req.body;
    job.updatedAt = nowISO();
    jobs.set(request_id, job);

    broadcastToRequest(request_id, { type: 'job_completed', request_id, status: job.status, response: job.response });

    console.log(`Callback received for ${request_id}; status=${job.status}`);
    return res.json({ ok: true });
  } catch (err) {
    console.error('callback error', err);
    return res.status(500).json({ error: 'internal error' });
  }
});

server.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
