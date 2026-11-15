// Plain Node.js HTTP server (no framework) for the Proof Gatekeeper agent.
//
// Endpoints:
//   GET  /agent  -> health check { ok: true, ... } (used by the platform
//                  health check and by operators; no auth needed)
//   POST /agent  -> signed task envelopes (see src/handler.js)
//   GET  /       -> same health payload (convenience)
//
// Run:  AGENT_GAMES_HMAC_SECRET=<platform secret> npm start
// Port: PORT env, default 8787. The registered endpoint must be a public
// HTTPS URL on the standard port (no localhost, no private IP, no custom
// ports) — terminate TLS at your host / reverse proxy, not here.
const http = require('http');
const { handleRawPost } = require('./src/handler');
const { SeenStore } = require('./src/seen');

const PORT = Number(process.env.PORT || 8787);
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const seen = new SeenStore();

if (!SECRET) {
  console.error('[gatekeeper] WARNING: AGENT_GAMES_HMAC_SECRET is not set — POST /agent will answer 500 until it is configured. GET /agent health still works.');
}

function healthPayload() {
  return {
    ok: true,
    agent: 'proof-gatekeeper',
    event: 'agent-games.proof-gatekeeper.v1',
    protocolVersion: 'v1',
    hmacConfigured: Boolean(SECRET),
    kurierEnabled: Boolean(process.env.KURIER_API_KEY),
    uptime_s: Math.floor(process.uptime()),
  };
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname.replace(/\/$/, '') || '/';

  if (req.method === 'GET' && (pathname === '/agent' || pathname === '/')) {
    const body = Buffer.from(JSON.stringify(healthPayload()), 'utf8');
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': body.length });
    res.end(body);
    return;
  }

  if (req.method === 'POST' && pathname === '/agent') {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > 1024 * 1024) { req.destroy(); return; } // 1 MB cap
      chunks.push(c);
    });
    req.on('end', async () => {
      try {
        const rawBody = Buffer.concat(chunks);
        const result = await handleRawPost({
          secret: SECRET,
          seen,
          rawBody,
          signatureHeader: req.headers['x-agent-games-signature'],
        });
        const headers = { 'content-type': 'application/json', 'content-length': result.body.length };
        if (result.signature) headers['x-agent-games-signature'] = result.signature;
        res.writeHead(result.status, headers);
        res.end(result.body);
      } catch (err) {
        console.error('[gatekeeper] handler error:', err);
        // Fail closed even on unexpected errors.
        const body = Buffer.from(JSON.stringify({ decision: 'REJECT', reason_code: 'INVALID_TASK', error: 'internal error' }), 'utf8');
        res.writeHead(200, { 'content-type': 'application/json', 'content-length': body.length });
        res.end(body);
      }
    });
    return;
  }

  res.writeHead(404, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ error: 'not found' }));
});

server.listen(PORT, () => {
  console.log(`[gatekeeper] listening on :${PORT} — POST /agent (HMAC required), GET /agent (health)`);
});

module.exports = { server };
