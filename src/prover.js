// Groth16 proof generation against the official gatekeeper circuit.
//
// Circuit facts (verified locally from the downloaded artifacts, 15 Nov 2026):
//   - Groth16 / BN128 (alt_bn128), Circom 2.x
//   - vk_hash (from https://agentgames.zkverify.io/api/circuit-info):
//     0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0
//   - Artifacts: circuits/gatekeeper.wasm (1,755,820 bytes, sha256
//     be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f)
//     and circuits/gatekeeper_final.zkey (309,750 bytes, sha256
//     adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d)
//   - Exported verification key: 13 public signals (nPublic = 13, IC = 14).
//   - 13 input signals (names NOT published on /build; recovered by
//     probing the compiled wasm — see README "Circuit inputs"):
//       taskId, registeredVkHash, proofVkHash, minimum, publicBalance,
//       expiryBlock, currentBlock, recipient, conditionRecipient,
//       amount, maxTransfer, decision, salt (private)
//   - Public signals emitted (verified empirically from a real proof
//     generated with these artifacts, 15 Nov 2026 — do NOT trust
//     input-declaration order here): [Poseidon(taskId, salt),
//     registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
//     currentBlock, recipient, conditionRecipient, amount, maxTransfer,
//     decision, taskId]. Note taskId is LAST. snarkjs computes them; we
//     never compute Poseidon ourselves.
//   - The circuit asserts decision == (all five field checks). Witness
//     generation FAILS for decision=1 on a trapped statement and for
//     decision=0 on a valid one — a wrong decision is unprovable. The
//     test harness asserts exactly that (test/run.js).
//
// Proof generation takes ~1-3 s locally, far inside the 60 s deadline.
const path = require('path');
const fs = require('fs');
const snarkjs = require('snarkjs');
const { toField, taskIdToField, deriveSalt } = require('./field');

const CIRCUITS_DIR = process.env.CIRCUITS_DIR || path.join(__dirname, '..', 'circuits');
const WASM_PATH = path.join(CIRCUITS_DIR, 'gatekeeper.wasm');
const ZKEY_PATH = path.join(CIRCUITS_DIR, 'gatekeeper_final.zkey');
const VK_PATH = path.join(CIRCUITS_DIR, 'verification_key.json');

let vkCache = null;
function loadVerificationKey() {
  if (!vkCache) {
    vkCache = JSON.parse(fs.readFileSync(VK_PATH, 'utf8'));
  }
  return vkCache;
}

/** Build the 13 circuit inputs from a task envelope + decision. Values are decimal strings (field elements mod p). */
function buildInputs(envelope, decision, hmacSecret) {
  const input = envelope.input;
  const decisionBit = decision === 'APPROVE' ? '1' : '0';
  return {
    taskId: taskIdToField(envelope.task_id).toString(),
    registeredVkHash: toField(input.registered_vk).toString(),
    proofVkHash: toField(input.proof_vk).toString(),
    minimum: toField(input.minimum).toString(),
    publicBalance: toField(input.public_balance).toString(),
    expiryBlock: toField(input.expiry_block).toString(),
    currentBlock: toField(input.current_block).toString(),
    recipient: toField(input.recipient).toString(),
    conditionRecipient: toField(input.condition_recipient).toString(),
    amount: toField(input.amount).toString(),
    maxTransfer: toField(input.max_transfer).toString(),
    decision: decisionBit,
    salt: deriveSalt(hmacSecret, envelope.task_id).toString(),
  };
}

/**
 * Generate a Groth16 proof for a decision.
 * @returns {Promise<{proof: object, publicSignals: string[]}>}
 * @throws if witness generation fails — which is precisely what happens
 *   for a WRONG decision (approve a trap / reject a valid condition).
 *   Callers must treat that as fail-closed REJECT, never as APPROVE.
 */
async function prove(envelope, decision, hmacSecret) {
  const inputs = buildInputs(envelope, decision, hmacSecret);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, WASM_PATH, ZKEY_PATH);
  return { proof, publicSignals: publicSignals.map(String) };
}

/** Verify a proof locally against the extracted verification key. */
async function verifyLocally(proof, publicSignals) {
  const vk = loadVerificationKey();
  return snarkjs.groth16.verify(vk, publicSignals, proof);
}

module.exports = { prove, verifyLocally, buildInputs, loadVerificationKey, WASM_PATH, ZKEY_PATH, VK_PATH };
