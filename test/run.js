// Local end-to-end test harness for the Proof Gatekeeper endpoint.
// Boots the REAL server (child process, ephemeral port, dummy HMAC secret
// — a test-only placeholder, never a real platform secret), replays
// spec-shaped envelopes, and verifies every generated proof locally with
// snarkjs groth16 verify against the verification key extracted from the
// official gatekeeper_final.zkey.
//
// Run:  npm test
// Exit code 0 = all checks pass.
const { spawn } = require('child_process');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const os = require('os');
const snarkjs = require('snarkjs');
const { envelope, CASES, PROOF_TX } = require('./fixtures');

const TEST_SECRET = 'test-secret-do-not-use-in-production-0000000000000000';
const PORT = 18787;
const BASE = `http://127.0.0.1:${PORT}`;
const VK_PATH = path.join(__dirname, '..', 'circuits', 'verification_key.json');

let pass = 0;
let fail = 0;
const failures = [];
function check(name, ok, detail = '') {
  if (ok) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; failures.push(name); console.log(`  FAIL  ${name} ${detail}`); }
}

function sign(body) {
  return crypto.createHmac('sha256', TEST_SECRET).update(body).digest('hex');
}
function verifyResponseSignature(bodyText, sig) {
  if (!sig) return false;
  const expected = crypto.createHmac('sha256', TEST_SECRET).update(Buffer.from(bodyText, 'utf8')).digest();
  const provided = Buffer.from(sig, 'hex');
  return provided.length === expected.length && crypto.timingSafeEqual(provided, expected);
}
async function postEnvelope(env, secretOverride) {
  const body = JSON.stringify(env);
  const t0 = Date.now();
  const res = await fetch(`${BASE}/agent`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-agent-games-signature': secretOverride === null ? '' : sign(body),
    },
    body,
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch (_) { /* keep null */ }
  return { status: res.status, text, json, sig: res.headers.get('x-agent-games-signature'), ms: Date.now() - t0 };
}

async function waitForServer(child, timeoutMs = 15000) {
  const t0 = Date.now();
  for (;;) {
    try {
      const res = await fetch(`${BASE}/agent`);
      if (res.ok) return true;
    } catch (_) { /* not up yet */ }
    if (Date.now() - t0 > timeoutMs) return false;
    await new Promise((r) => setTimeout(r, 200));
  }
}

async function main() {
  console.log('== Proof Gatekeeper local test harness ==');
  console.log(`   server: node server.js on :${PORT} (dummy HMAC secret, test only)`);
  const seenPath = path.join(os.tmpdir(), `gk-seen-test-${process.pid}.json`);
  const child = spawn('node', ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: TEST_SECRET, SEEN_STORE_PATH: seenPath },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (d) => process.stdout.write('[server] ' + d.toString()));
  child.stderr.on('data', (d) => process.stdout.write('[server:err] ' + d.toString()));

  try {
    check('server boots + GET /agent health', await waitForServer(child));
    const health = await (await fetch(`${BASE}/agent`)).json();
    check('health payload ok + hmacConfigured', health.ok === true && health.hmacConfigured === true, JSON.stringify(health));

    // --- HMAC gate ---
    console.log('-- HMAC gate (verified BEFORE parsing) --');
    const noSig = await postEnvelope(envelope('gk_test_nosig', { proof_tx: '0x99c1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708ff1' }), null);
    // Empty signature header: fetch sends '' — server must 401.
    check('missing/empty signature -> 401', noSig.status === 401, `got ${noSig.status}`);
    // Tamper after signing: sign one body, send a different body with the old signature.
    const tamperedBody = JSON.stringify(envelope('gk_test_tamper2', { proof_tx: '0x88c1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708ff1', amount: '1' }));
    const untamperedBody = JSON.stringify(envelope('gk_test_tamper2', { proof_tx: '0x88c1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708ff1', amount: '500' }));
    const tRes = await fetch(`${BASE}/agent`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-agent-games-signature': sign(untamperedBody) },
      body: tamperedBody,
    });
    check('tampered body with stale signature -> 401', tRes.status === 401, `got ${tRes.status}`);
    const wrongSecretBody = JSON.stringify(envelope('gk_test_wrongsecret', {}));
    const wrongSecretSig = crypto.createHmac('sha256', 'wrong-secret').update(wrongSecretBody).digest('hex');
    const wRes = await fetch(`${BASE}/agent`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-agent-games-signature': wrongSecretSig },
      body: wrongSecretBody,
    });
    check('wrong secret -> 401', wRes.status === 401, `got ${wRes.status}`);

    // --- Preflight ---
    console.log('-- preflight --');
    const pre = await postEnvelope({ type: 'agent-games.preflight.v1' });
    check('preflight -> { ok: true, protocolVersion: v1 }', pre.status === 200 && pre.json && pre.json.ok === true && pre.json.protocolVersion === 'v1', pre.text);
    check('preflight response is HMAC-signed', verifyResponseSignature(pre.text, pre.sig));

    // --- Decision + proof cases ---
    console.log('-- decision logic + Groth16 proofs (verified locally with snarkjs) --');
    const vk = JSON.parse(fs.readFileSync(VK_PATH, 'utf8'));
    let maxMs = 0;
    for (const c of CASES) {
      const env = envelope(c.taskId, c.input);
      const r = await postEnvelope(env);
      maxMs = Math.max(maxMs, r.ms);
      const decisionOk = r.status === 200 && r.json && r.json.decision === c.expect[0] && r.json.reason_code === c.expect[1];
      check(`${c.name}: ${c.expect[0]}/${c.expect[1]}`, decisionOk, r.text.slice(0, 200));
      check(`${c.name}: response HMAC signature verifies`, verifyResponseSignature(r.text, r.sig));
      if (c.proof) {
        const hasProof = r.json && r.json.proof && Array.isArray(r.json.public_signals) && r.json.public_signals.length === 13;
        check(`${c.name}: proof + 13 public signals present`, hasProof);
        if (hasProof) {
          const t0 = Date.now();
          const ok = await snarkjs.groth16.verify(vk, r.json.public_signals, r.json.proof);
          check(`${c.name}: snarkjs groth16 verify OK (${Date.now() - t0} ms)`, ok === true);
          // Public signals, verified empirically against the downloaded
          // circuit (probe, 15 Nov 2026): index 0 is Poseidon(taskId,
          // salt); indices 1..11 are registeredVkHash, proofVkHash,
          // minimum, publicBalance, expiryBlock, currentBlock, recipient,
          // conditionRecipient, amount, maxTransfer, decision; index 12
          // is taskId (SHA-256 mod p). NOTE: taskId is LAST, not second
          // — do not trust summaries that list the inputs in declaration
          // order; this ordering was measured from a real proof.
          const decisionSignal = r.json.public_signals[11];
          check(`${c.name}: public signal decision bit == ${c.expect[0] === 'APPROVE' ? 1 : 0}`, decisionSignal === (c.expect[0] === 'APPROVE' ? '1' : '0'), `got ${decisionSignal}`);
        }
      }
      console.log(`        (round-trip ${r.ms} ms)`);
    }
    check('all round-trips well under 60 s deadline', maxMs < 60000, `max ${maxMs} ms`);
    console.log(`        slowest round-trip: ${maxMs} ms`);

    // --- PROOF_REUSED: same proof_tx as the valid task, new task_id ---
    console.log('-- proof reuse --');
    const reused = await postEnvelope(envelope('gk_test_reuse_009', { proof_tx: '0x11c1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708ff1' }));
    check('reused proof_tx -> REJECT/PROOF_REUSED', reused.json && reused.json.decision === 'REJECT' && reused.json.reason_code === 'PROOF_REUSED', reused.text.slice(0, 200));
    check('PROOF_REUSED carries no proof (per event page)', reused.json && !reused.json.proof);

    // --- Idempotent redelivery ---
    console.log('-- idempotency --');
    const first = await postEnvelope(envelope('gk_test_valid_001', {}));
    const second = await postEnvelope(envelope('gk_test_valid_001', {}));
    check('redelivery of same task_id returns cached APPROVE (not reuse)', second.json && second.json.decision === 'APPROVE' && second.json.reason_code === 'VALID_CONDITION', second.text.slice(0, 200));
    check('redelivered body is byte-identical to first response', first.text === second.text);

    // --- Circuit is the referee: wrong decisions are unprovable ---
    console.log('-- circuit referee (direct prover, no server) --');
    const { prove } = require('../src/prover');
    const validEnv = envelope('gk_test_referee_valid', {});
    let threw = false;
    try { await prove(validEnv, 'REJECT', TEST_SECRET); } catch (_) { threw = true; }
    check('rejecting a VALID condition: fullProve throws (unprovable)', threw);
    const trapEnv = envelope('gk_test_referee_trap', { recipient: '0xBeef000000000000000000000000000000000001' });
    threw = false;
    try { await prove(trapEnv, 'APPROVE', TEST_SECRET); } catch (_) { threw = true; }
    check('approving a RECIPIENT_MISMATCH trap: fullProve throws (unprovable)', threw);
    const okProve = await prove(validEnv, 'APPROVE', TEST_SECRET);
    const okVerify = await snarkjs.groth16.verify(vk, okProve.publicSignals, okProve.proof);
    check('direct prove(valid, APPROVE) verifies OK', okVerify === true);
    console.log(`        proof size: ${JSON.stringify(okProve.proof).length} bytes JSON, ${okProve.publicSignals.length} public signals`);
  } finally {
    child.kill('SIGTERM');
    try { fs.unlinkSync(seenPath); } catch (_) { /* ignore */ }
  }

  console.log(`\n== RESULT: ${pass} passed, ${fail} failed ==`);
  if (failures.length) console.log('Failed checks:\n - ' + failures.join('\n - '));
  process.exit(fail ? 1 : 0);
}

main().catch((err) => { console.error(err); process.exit(2); });
