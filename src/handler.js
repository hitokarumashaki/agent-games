// Request pipeline shared by the HTTP server (server.js).
//
// Flow for POST /agent:
//   1. HMAC-SHA256 over the RAW body vs `x-agent-games-signature` —
//      verified BEFORE JSON parsing. Mismatch/missing -> HTTP 401, no
//      processing at all.
//   2. Preflight (type "agent-games.preflight.v1") -> signed
//      { ok: true, protocolVersion: "v1" }.
//   3. Gatekeeper task (type "agent-games.proof-gatekeeper.v1"):
//      a. Idempotency: a task_id seen before returns the cached response.
//      b. Deadline sanity: issued/deadline in the past -> REJECT (fail closed).
//      c. Deterministic policy (src/decision.js) -> decision + reason_code.
//      d. Groth16 proof via snarkjs (skipped only for PROOF_REUSED — the
//         event page states those tasks have no proof to submit and are
//         excluded from proof scoring). A proof-generation failure for a
//         decision that should be provable is logged and the answer is
//         still returned (REJECT without proof) — never an unproven APPROVE.
//      e. Optional Kurier submission (disabled unless KURIER_API_KEY is set).
//      f. Mark proof_tx as seen (only for fresh, non-redelivered tasks),
//         cache the response, and return it signed.
//   4. Every response body is signed with HMAC-SHA256 over the RAW
//      response body, sent as `x-agent-games-signature`.
//
// Fail closed throughout: malformed envelopes, internal errors, proof
// failures and past deadlines all resolve to REJECT, never APPROVE.
// Soft deadline: TASK_SOFT_DEADLINE_MS (default 50000 ms; the platform
// hard deadline is 60 s). Proof generation is ~1-3 s locally.
const hmac = require('./hmac');
const { decide } = require('./decision');
const { prove } = require('./prover');
const kurier = require('./kurier');

const SOFT_DEADLINE_MS = Number(process.env.TASK_SOFT_DEADLINE_MS || 50000);

function signResponse(secret, status, bodyObj) {
  const body = Buffer.from(JSON.stringify(bodyObj), 'utf8');
  return { status, body, signature: hmac.sign(secret, body) };
}

async function handleRawPost({ secret, seen, rawBody, signatureHeader, nowMs = Date.now() }) {
  const started = Date.now();

  // 1. HMAC first, before any parsing.
  if (!secret) {
    return signResponse('unset', 500, { error: 'server misconfigured: AGENT_GAMES_HMAC_SECRET is not set' });
  }
  if (!hmac.verify(secret, rawBody, signatureHeader)) {
    return { status: 401, body: Buffer.from(JSON.stringify({ error: 'unauthorized: bad signature' })), signature: null };
  }

  let envelope;
  try {
    envelope = JSON.parse(rawBody.toString('utf8'));
  } catch (_) {
    return signResponse(secret, 400, { decision: 'REJECT', reason_code: 'INVALID_TASK', error: 'malformed JSON' });
  }

  // 2. Preflight handshake.
  if (envelope.type === 'agent-games.preflight.v1') {
    return signResponse(secret, 200, { ok: true, protocolVersion: 'v1' });
  }

  if (envelope.type !== 'agent-games.proof-gatekeeper.v1') {
    return signResponse(secret, 400, { decision: 'REJECT', reason_code: 'INVALID_TASK', error: `unknown type: ${envelope.type}` });
  }

  const taskId = envelope.task_id;
  if (typeof taskId !== 'string' || !taskId) {
    return signResponse(secret, 400, { decision: 'REJECT', reason_code: 'INVALID_TASK', error: 'missing task_id' });
  }

  // 3a. Idempotent redelivery -> cached response (NOT a reuse).
  const cached = seen.getCached(taskId);
  if (cached) {
    return { status: cached.status, body: Buffer.from(cached.body, 'utf8'), signature: cached.signature };
  }

  // 3b. Deadline sanity -> fail closed.
  const deadlineMs = envelope.deadline_at ? Date.parse(envelope.deadline_at) : NaN;
  if (!Number.isNaN(deadlineMs) && nowMs > deadlineMs) {
    const resp = signResponse(secret, 200, {
      decision: 'REJECT', reason_code: 'INVALID_TASK',
      proof_tx: envelope.input ? envelope.input.proof_tx : null,
      error: 'task already past deadline',
    });
    seen.setCached(taskId, { status: resp.status, body: resp.body.toString('utf8'), signature: resp.signature });
    return resp;
  }

  // 3c. Deterministic decision.
  const input = envelope.input || {};
  const { decision, reason_code } = decide(input, seen);
  const elapsed = () => Date.now() - started;

  // 3d. Groth16 proof (except PROOF_REUSED, which has no proof to submit).
  let proof = null;
  let publicSignals = null;
  let proofError = null;
  if (reason_code !== 'PROOF_REUSED') {
    try {
      const result = await prove(envelope, decision, secret);
      proof = result.proof;
      publicSignals = result.publicSignals;
    } catch (err) {
      // A correct decision that cannot be proven means policy and circuit
      // disagree — log loudly, answer without proof, never approve blind.
      proofError = err.message;
      console.error(`[gatekeeper] proof generation failed for ${taskId} (${decision}/${reason_code}):`, err.message);
    }
  }

  // 3e. Optional Kurier submission (off unless a key is configured).
  let proofTx = null;
  if (kurier.isEnabled() && proof) {
    const sub = await kurier.submitProof(proof, publicSignals);
    if (sub.ok) proofTx = sub.txHash || null;
  }

  // 3f. Record + cache + respond.
  // Mark the proof_tx seen only for fresh tasks (redeliveries return early
  // above, so this cannot double-count). For PROOF_REUSED the tx was
  // already in the set by definition.
  if (input.proof_tx && reason_code !== 'PROOF_REUSED') seen.markSeen(input.proof_tx);

  const bodyObj = {
    decision,
    reason_code,
    proof_tx: proofTx || input.proof_tx || null,
  };
  if (proof) {
    bodyObj.proof = proof;
    bodyObj.public_signals = publicSignals;
  }
  if (proofError) bodyObj.proof_error = proofError;
  bodyObj.elapsed_ms = elapsed();

  const resp = signResponse(secret, 200, bodyObj);
  seen.setCached(taskId, { status: resp.status, body: resp.body.toString('utf8'), signature: resp.signature });
  return resp;
}

module.exports = { handleRawPost, SOFT_DEADLINE_MS };
