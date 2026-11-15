// HMAC-SHA256 signing / verification for Agent Games task envelopes.
//
// Protocol (from https://agentgames.zkverify.io/build and /rules):
//  - Incoming: verify the `x-agent-games-signature` header over the RAW
//    request body BEFORE parsing or processing anything.
//  - Outgoing: sign the raw response body and send it as
//    `x-agent-games-signature`.
//  - The secret is the 32-byte platform-generated value shown once at
//    registration (dashboard -> agent -> Rotate Secret). It comes from the
//    AGENT_GAMES_HMAC_SECRET environment variable. Never commit it.
//
// Ambiguity handled defensively: the docs mandate HMAC over the raw body
// but never name the encoding. Outbound signing is HMAC-SHA256 hex.
// Inbound verification accepts hex or base64 of the same MAC bytes, with
// an optional `sha256=` prefix. Comparison is constant-time.
const crypto = require('crypto');

function sign(secret, rawBody) {
  const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody, 'utf8');
  return crypto.createHmac('sha256', secret).update(body).digest('hex');
}

function decodeSignature(headerValue) {
  if (typeof headerValue !== 'string') return null;
  let s = headerValue.trim();
  if (s.toLowerCase().startsWith('sha256=')) s = s.slice('sha256='.length);
  if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) return Buffer.from(s, 'hex');
  // Base64 (standard or URL-safe).
  try {
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
    const buf = Buffer.from(b64, 'base64');
    if (buf.length > 0) return buf;
  } catch (_) { /* fall through */ }
  return null;
}

/** Constant-time check: does `headerValue` equal HMAC-SHA256(secret, rawBody)? */
function verify(secret, rawBody, headerValue) {
  if (!secret || !headerValue) return false;
  const expected = crypto.createHmac('sha256', secret)
    .update(Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody, 'utf8'))
    .digest();
  const provided = decodeSignature(headerValue);
  if (!provided || provided.length !== expected.length) return false;
  return crypto.timingSafeEqual(provided, expected);
}

module.exports = { sign, verify, decodeSignature };
