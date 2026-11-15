// Field-element helpers for the BN128 (alt_bn128) scalar field used by the
// gatekeeper Groth16 circuit (Circom 2.x, Groth16/BN128).
//
// Rule (verified against the official circuit, see test/run.js): every
// envelope value is reduced modulo the field prime p. A 32-byte hash does
// NOT fit in the field, so reduction is what preserves the equality checks
// the circuit performs — the circuit compares reduced values on both sides.
const crypto = require('crypto');

// BN128 scalar-field prime.
const P = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

function modP(x) {
  const r = x % P;
  return r >= 0n ? r : r + P;
}

/** Convert a hex string ("0x…"), decimal string, or number to a field element (BigInt mod p). */
function toField(value) {
  if (typeof value === 'bigint') return modP(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error(`toField: not a non-negative safe integer: ${value}`);
    return BigInt(value);
  }
  if (typeof value === 'string') {
    const s = value.trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) return modP(BigInt(s));
    if (/^[0-9]+$/.test(s)) return modP(BigInt(s));
    throw new Error(`toField: unsupported string value: ${value}`);
  }
  throw new Error(`toField: unsupported type: ${typeof value}`);
}

/**
 * task_id -> field element.
 * Free-form ids (e.g. "gk_24_9d1") are SHA-256 hashed and reduced mod p;
 * numeric / 0x ids are used directly (reduced mod p).
 */
function taskIdToField(taskId) {
  if (typeof taskId !== 'string' || taskId.length === 0) throw new Error('taskIdToField: task_id must be a non-empty string');
  if (/^0x[0-9a-fA-F]+$/.test(taskId) || /^[0-9]+$/.test(taskId)) return toField(taskId);
  const digest = crypto.createHash('sha256').update(taskId, 'utf8').digest('hex');
  return modP(BigInt('0x' + digest));
}

/**
 * Deterministic per-task circuit salt (private input).
 * salt = HMAC-SHA256(secret, "gatekeeper-salt:" + task_id) mod p.
 * Deterministic so a redelivered task reproduces identical proof inputs
 * (and therefore the identical cached response) instead of a fresh proof.
 * The secret here is the platform HMAC secret from the environment — never
 * a committed or hard-coded value.
 */
function deriveSalt(hmacSecret, taskId) {
  if (!hmacSecret) throw new Error('deriveSalt: HMAC secret is required');
  const mac = crypto.createHmac('sha256', hmacSecret).update(`gatekeeper-salt:${taskId}`, 'utf8').digest('hex');
  return modP(BigInt('0x' + mac));
}

module.exports = { P, modP, toField, taskIdToField, deriveSalt };
