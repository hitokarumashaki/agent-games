// Deterministic APPROVE/REJECT policy for Proof Gatekeeper.
//
// Mirrors the circuit exactly, boundaries included. The circuit asserts
// decision == (all five field checks), so a decision that disagrees with
// the checks cannot even produce a witness — the policy and the circuit
// must agree, and this module is the single place where the rule lives.
//
// APPROVE only if ALL of these hold:
//   1. proof_vk == registered_vk            (VK_SUBSTITUTION otherwise)
//   2. proof_tx not seen before             (PROOF_REUSED otherwise)
//   3. public_balance >= minimum            (THRESHOLD_MISMATCH otherwise)
//   4. current_block < expiry_block         (EXPIRED_CONDITION otherwise)
//   5. recipient == condition_recipient     (RECIPIENT_MISMATCH otherwise)
//   6. amount <= max_transfer               (AMOUNT_OVERFLOW otherwise)
//
// Check order matters for reason_code: VK first, then reuse, then the
// remaining field checks in the order above. Fail closed: any malformed
// or missing field -> REJECT with reason_code INVALID_TASK (a local
// fallback outside the documented 7-code taxonomy, only reachable off
// the scored paths).
//
// The 7 trap varieties and their documented frequencies (~% of tasks):
//   VALID_CONDITION    ~50%  APPROVE — everything passes
//   VK_SUBSTITUTION    ~13%  REJECT — proof verifies, VK does not match
//   PROOF_REUSED       ~11%  REJECT — proof_tx already accepted before
//   THRESHOLD_MISMATCH ~8%   REJECT — public_balance < minimum
//   EXPIRED_CONDITION  ~6%   REJECT — current_block >= expiry_block
//   RECIPIENT_MISMATCH ~6%   REJECT — recipient != condition_recipient
//   AMOUNT_OVERFLOW    ~6%   REJECT — amount > max_transfer
//
// Scoring (per task): correct +12, wrong APPROVE -6, wrong REJECT -3,
// timeout -2, missing/invalid proof -2, reliability bonus +0..+5/round.
// Wrong approvals cost double wrong rejections — when in doubt, REJECT.

const REASON_CODES = [
  'VALID_CONDITION',
  'VK_SUBSTITUTION',
  'PROOF_REUSED',
  'THRESHOLD_MISMATCH',
  'EXPIRED_CONDITION',
  'RECIPIENT_MISMATCH',
  'AMOUNT_OVERFLOW',
];

function asBigInt(value, field) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error(`${field}: not a safe integer`);
    return BigInt(value);
  }
  if (typeof value === 'string') {
    const s = value.trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
    if (/^-?[0-9]+$/.test(s)) return BigInt(s);
    throw new Error(`${field}: not a number: ${value}`);
  }
  throw new Error(`${field}: unsupported type ${typeof value}`);
}

function sameAddress(a, b) {
  // Addresses are compared case-insensitively (EIP-55 checksum case varies).
  return String(a).trim().toLowerCase() === String(b).trim().toLowerCase();
}

/**
 * Decide a task.
 * @param {object} input  the task's `input` object (see /events/proof-gatekeeper sample payload)
 * @param {object} seen   object with has(proofTx) -> bool
 * @returns {{decision: 'APPROVE'|'REJECT', reason_code: string}}
 */
function decide(input, seen) {
  if (!input || typeof input !== 'object') {
    return { decision: 'REJECT', reason_code: 'INVALID_TASK' };
  }
  try {
    const required = ['registered_vk', 'proof_vk', 'minimum', 'public_balance',
      'expiry_block', 'current_block', 'recipient', 'condition_recipient',
      'amount', 'max_transfer', 'proof_tx'];
    for (const f of required) {
      if (input[f] === undefined || input[f] === null || input[f] === '') {
        return { decision: 'REJECT', reason_code: 'INVALID_TASK' };
      }
    }

    // 1. Verification key must match the registered condition VK.
    if (String(input.proof_vk).trim().toLowerCase() !== String(input.registered_vk).trim().toLowerCase()) {
      return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };
    }

    // 2. Proof reference must not have been used before.
    if (seen && seen.has(String(input.proof_tx))) {
      return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
    }

    // 3. Public balance must meet the minimum threshold.
    if (asBigInt(input.public_balance, 'public_balance') < asBigInt(input.minimum, 'minimum')) {
      return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
    }

    // 4. Condition must not have expired (block height).
    if (asBigInt(input.current_block, 'current_block') >= asBigInt(input.expiry_block, 'expiry_block')) {
      return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
    }

    // 5. Recipient must match the condition recipient.
    if (!sameAddress(input.recipient, input.condition_recipient)) {
      return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
    }

    // 6. Amount must not exceed the single-transfer cap.
    if (asBigInt(input.amount, 'amount') > asBigInt(input.max_transfer, 'max_transfer')) {
      return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };
    }

    return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
  } catch (err) {
    // Any malformed numeric field etc. -> fail closed.
    return { decision: 'REJECT', reason_code: 'INVALID_TASK' };
  }
}

module.exports = { decide, REASON_CODES };
