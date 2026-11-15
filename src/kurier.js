// Optional Kurier submission of the locally generated proof to zkVerify
// mainnet, returning an on-chain proof_tx for the response.
//
// STATUS: UNVERIFIED AND DISABLED BY DEFAULT.
//  - No Kurier API key exists for this agent and no submission has ever
//    been made from this codebase. Nothing here spends anything.
//  - The /build guide describes the Kurier flow only in general terms
//    (REST, get a mainnet API key, register the verification key once,
//    submit proofs with its vk hash, poll until Finalized). The exact
//    Kurier endpoint paths / request shapes were NOT confirmed from
//    Kurier's own docs in this build, so this module is a clearly-marked
//    integration point, not a tested integration.
//  - The response path does NOT depend on Kurier: when no key is
//    configured the agent still answers with the local Groth16 proof +
//    public_signals, which is what /build says to include in the
//    response ("include the proof in your response"). The event page's
//    expected response shape lists proof_tx; practice tasks (preflight +
//    >=1 practice task, required before scored rounds) are the place to
//    confirm whether the platform accepts proof+public_signals alone or
//    requires a Kurier proof_tx.
//  - If Kurier is enabled later: set KURIER_API_KEY (and optionally
//    KURIER_API_URL, KURIER_POLL_BUDGET_MS, default 15000). The poll
//    budget is bounded so a slow finalization can never eat the 60 s
//    task deadline — finalization continues server-side at Kurier.
//  - submitProof() never throws: any failure returns { ok: false } and
//    the caller answers without proof_tx.
const VK_HASH = process.env.GATEKEEPER_VK_HASH
  || '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';

function isEnabled() {
  return Boolean(process.env.KURIER_API_KEY);
}

/**
 * Submit a proof to Kurier.
 * TODO (before enabling): confirm the submit + status endpoint paths and
 * request/response shapes against Kurier's current docs, then wire them
 * here and test against practice mode. Until then this returns not-ok
 * without making any network call.
 */
async function submitProof(/* proof, publicSignals */) {
  if (!isEnabled()) return { ok: false, reason: 'kurier-not-configured' };
  // Deliberately not implemented: endpoint shape unconfirmed.
  return { ok: false, reason: 'kurier-integration-not-verified' };
}

module.exports = { isEnabled, submitProof, VK_HASH };
