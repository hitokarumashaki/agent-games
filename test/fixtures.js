// Sample task envelopes, shaped exactly like the sample payload on
// https://agentgames.zkverify.io/events/proof-gatekeeper.
// The valid fixture uses the registered gatekeeper vk_hash for BOTH
// registered_vk and proof_vk:
//   0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0
// (verified from https://agentgames.zkverify.io/api/circuit-info).
// The event page's own sample is a VK_SUBSTITUTION trap
// (registered 0x7d3a...f291 vs proof 0xa4c1...b8ff) — do not use it as
// a "valid" case.
const VK_HASH = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const OTHER_VK = '0xa4c1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708ff1';
const RECIPIENT = '0xDe42a1b2c3d4e5f6a7b8c9d0e1f2a3b49f01';
const OTHER_RECIPIENT = '0xBeef000000000000000000000000000000000001';
const PROOF_TX = '0xa4c1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708ff1';

function baseInput(overrides = {}) {
  return {
    registered_vk: VK_HASH,
    proof_vk: VK_HASH,
    minimum: '1000',
    public_balance: '1460',
    expiry_block: 19842201,
    current_block: 19832000,
    recipient: RECIPIENT,
    condition_recipient: RECIPIENT,
    amount: '500',
    max_transfer: '1000',
    proof_tx: PROOF_TX,
    ...overrides,
  };
}

function envelope(taskId, inputOverrides = {}, extra = {}) {
  const now = new Date();
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: taskId,
    mode: 'competition',
    issued_at: now.toISOString(),
    // Deadline 55 s out: inside the 60 s platform window for the test run.
    deadline_at: new Date(now.getTime() + 55_000).toISOString(),
    input: baseInput(inputOverrides),
    ...extra,
  };
}

const CASES = [
  { name: 'VALID_CONDITION', taskId: 'gk_test_valid_001', input: { proof_tx: '0x11c1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708ff1' }, expect: ['APPROVE', 'VALID_CONDITION'], proof: true },
  { name: 'VK_SUBSTITUTION', taskId: 'gk_test_vk_002', input: { proof_vk: OTHER_VK, proof_tx: '0x22c1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708ff1' }, expect: ['REJECT', 'VK_SUBSTITUTION'], proof: true },
  { name: 'THRESHOLD_MISMATCH', taskId: 'gk_test_thr_003', input: { public_balance: '999', proof_tx: '0x33c1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708ff1' }, expect: ['REJECT', 'THRESHOLD_MISMATCH'], proof: true },
  { name: 'EXPIRED_CONDITION', taskId: 'gk_test_exp_004', input: { current_block: 19842201, proof_tx: '0x44c1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708ff1' }, expect: ['REJECT', 'EXPIRED_CONDITION'], proof: true },
  { name: 'RECIPIENT_MISMATCH', taskId: 'gk_test_rec_005', input: { condition_recipient: OTHER_RECIPIENT, proof_tx: '0x55c1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708ff1' }, expect: ['REJECT', 'RECIPIENT_MISMATCH'], proof: true },
  { name: 'AMOUNT_OVERFLOW', taskId: 'gk_test_amt_006', input: { amount: '1001', proof_tx: '0x66c1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708ff1' }, expect: ['REJECT', 'AMOUNT_OVERFLOW'], proof: true },
  // Boundary cases: equality is allowed, not a trap.
  { name: 'BOUNDARY balance==minimum', taskId: 'gk_test_bnd_007', input: { public_balance: '1000', proof_tx: '0xc4c1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708ff1' }, expect: ['APPROVE', 'VALID_CONDITION'], proof: true },
  { name: 'BOUNDARY amount==max', taskId: 'gk_test_bnd_008', input: { amount: '1000', proof_tx: '0xb4c1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708ff1' }, expect: ['APPROVE', 'VALID_CONDITION'], proof: true },
];

module.exports = { VK_HASH, OTHER_VK, RECIPIENT, OTHER_RECIPIENT, PROOF_TX, baseInput, envelope, CASES };
