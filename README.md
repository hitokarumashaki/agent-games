# Proof Gatekeeper Agent — zkVerify Agent Games Season 01

Public repo (Akmal's personal GitHub account — Agent Games does not
support org-owned repos):

**https://github.com/hitokamurashaki/agent-games**

This directory is the Gatekeeper agent. The same repo is also the
submission for the **Wildcard** track (repo + live endpoint + write-up,
submit before 21 Nov 2026). Nothing in this repo is pushed to GitHub
automatically — pushing is a manual step for Akmal (see
[Push to GitHub](#push-to-github)).

## What this is

An HTTPS agent endpoint for the **Proof Gatekeeper** event. The
platform POSTs signed task envelopes; this service verifies the HMAC,
makes a deterministic APPROVE/REJECT decision, generates a real
Groth16 proof locally with snarkjs against the official gatekeeper
circuit, and returns a signed response — well inside the 60-second
hard deadline (typical round-trip ~0.3–0.4 s warm in local tests).

Fail closed throughout: malformed envelopes, internal errors, and
proof-generation failures all resolve to REJECT, never to an unproven
APPROVE.

## Competition status (15 Nov 2026)

- Season 01: 21 Oct – 21 Nov 2026. Gatekeeper: 8 daily rounds, 13–21 Nov,
  **17:30–03:30 WIB**, 8 tasks/agent/round, scores cumulative.
  Rounds 1–2 already done (missed). **Round 3: today 15 Nov 17:30 WIB.
  Target readiness: Round 4, 16 Nov 17:30 WIB.**
- Prize: 100,000 VFY for this track (1st 50,000 / 2nd 30,000 / 3rd
  20,000). Judging/announcement 22–30 Nov 2026.
- Scoring per task: correct +12, wrong APPROVE −6, wrong REJECT −3,
  timeout −2, missing/invalid proof −2, reliability bonus +0..+5/round.
  Wrong approvals cost double wrong rejections — when in doubt, REJECT.

## Architecture

```
POST /agent
  │
  ├─ 1. HMAC-SHA256 over the RAW body vs `x-agent-games-signature`
  │     (verified BEFORE JSON parsing; mismatch → HTTP 401)
  ├─ 2. type = "agent-games.preflight.v1"
  │     → signed `{ ok: true, protocolVersion: "v1" }`
  └─ 3. type = "agent-games.proof-gatekeeper.v1"
        ├─ idempotency cache (same task_id → cached response)
        ├─ deadline/timestamp sanity → fail closed
        ├─ deterministic policy (src/decision.js) → decision + reason_code
        ├─ snarkjs fullProve with gatekeeper.wasm / gatekeeper_final.zkey
        │    (skipped only for PROOF_REUSED — documented as having no proof)
        ├─ Kurier submit (disabled unless KURIER_API_KEY is set; see below)
        └─ signed JSON response
```

### File layout

| Path | Purpose |
| --- | --- |
| `server.js` | Plain Node HTTP server (`npm start`). `GET /agent` = health check. |
| `src/handler.js` | Framework-agnostic request pipeline. |
| `src/hmac.js` | HMAC sign/verify (hex/base64 accepted inbound, hex outbound). |
| `src/field.js` | Field-element conversion (values mod BN128 prime), taskId hash, salt derivation. |
| `src/decision.js` | Deterministic policy + the 7 trap varieties. |
| `src/prover.js` | snarkjs `groth16.fullProve` wrapper + local verification. |
| `src/kurier.js` | Optional Kurier submission (disabled by default, untested — see below). |
| `src/seen.js` | proof_tx seen-set + response cache, JSON-file backed. |
| `circuits/` | Official artifacts: `gatekeeper.wasm`, `gatekeeper_final.zkey`, `verification_key.json` (extracted), `circuit-info.json`. |
| `scripts/download-circuits.sh` | Re-download + verify the official artifacts. |
| `test/` | Local end-to-end harness (`npm test`) + fixtures. |

## Decision rules

APPROVE only if **all** of these hold (boundaries included):

1. `proof_vk == registered_vk`
2. `proof_tx` not seen before
3. `public_balance >= minimum`
4. `current_block < expiry_block`
5. `recipient == condition_recipient`
6. `amount <= max_transfer`

### The 7 trap varieties

| Reason code | Meaning | ~% of tasks |
| --- | --- | --- |
| `VALID_CONDITION` | Everything passes → APPROVE | ~50% |
| `VK_SUBSTITUTION` | Proof verifies, but its VK ≠ registered VK | ~13% |
| `PROOF_REUSED` | `proof_tx` already accepted before → REJECT, no proof attached | ~11% |
| `THRESHOLD_MISMATCH` | `public_balance < minimum` | ~8% |
| `EXPIRED_CONDITION` | `current_block >= expiry_block` | ~6% |
| `RECIPIENT_MISMATCH` | Recipient ≠ condition recipient | ~6% |
| `AMOUNT_OVERFLOW` | `amount > max_transfer` | ~6% |

## The circuit (verified locally, not taken on trust)

- Groth16 / BN128, Circom 2.x. `vk_hash` (from
  `https://agentgames.zkverify.io/api/circuit-info`):
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
- Artifacts: `gatekeeper.wasm` (1,755,820 bytes, sha256
  `be00aefe…92764f`) and `gatekeeper_final.zkey` (309,750 bytes, sha256
  `adfe95a4…01af80d`). Re-download with `npm run circuits`.
- Exported verification key: **13 public signals** (`nPublic = 13`).
- 13 input signals (names are NOT published on the /build page; they
  were recovered from the compiled wasm by probing it, and confirmed
  here by actually proving):
  `taskId, registeredVkHash, proofVkHash, minimum, publicBalance,
  expiryBlock, currentBlock, recipient, conditionRecipient, amount,
  maxTransfer, decision, salt (private)`.
- Public signals, **verified empirically from a real proof** (15 Nov
  2026): `[Poseidon(taskId, salt), registeredVkHash, proofVkHash,
  minimum, publicBalance, expiryBlock, currentBlock, recipient,
  conditionRecipient, amount, maxTransfer, decision, taskId]`.
  Note `taskId` is **last**, not second — summaries that list the
  inputs in declaration order get this wrong.
- Field elements are envelope values reduced mod the BN128 prime (a
  32-byte hash does not fit the field; reduction preserves the
  equality checks). Free-form `task_id` values are SHA-256 hashed,
  mod p. `salt` is derived deterministically as
  `HMAC(secret, "gatekeeper-salt:" + task_id) mod p`, so a redelivered
  task reproduces identical proof inputs.
- The circuit asserts `decision == (all five field checks)`:
  witness generation **fails** for `decision=1` on a trapped statement
  and for `decision=0` on a valid one. A wrong decision is
  unprovable — the circuit is the referee. The test harness asserts
  exactly that.

## Response shape

All fields the spec mentions, so either verification path finds what
it needs:

```json
{
  "decision": "APPROVE",
  "reason_code": "VALID_CONDITION",
  "proof": { "pi_a": ["…"], "pi_b": [["…"]], "pi_c": ["…"], "protocol": "groth16", "curve": "bn128" },
  "public_signals": ["<13 field elements>"],
  "proof_tx": "0x…"
}
```

plus the `x-agent-games-signature` header (HMAC-SHA256 over the raw
response body). For `PROOF_REUSED` the response carries no proof —
the event page states those tasks "have no proof to submit and are
excluded" from proof scoring.

## Environment variables

| Variable | Required | Notes |
| --- | --- | --- |
| `AGENT_GAMES_HMAC_SECRET` | yes | Platform-generated; dashboard → agent → **Rotate Secret**, copy the one-time plaintext. Never a local placeholder, never committed. |
| `KURIER_API_KEY` | no | Mainnet Kurier key. If unset, submission is skipped and the agent still answers with proof + public_signals. **Untested — see below.** |
| `KURIER_API_URL` | no | Default `https://api.kurier.xyz/api/v1`. |
| `KURIER_POLL_BUDGET_MS` | no | Default 15000. Bounded so slow finalization can never eat the 60 s deadline. |
| `GATEKEEPER_VK_HASH` | no | Defaults to the registered gatekeeper vk_hash. |
| `TASK_SOFT_DEADLINE_MS` | no | Default 50000 (hard platform deadline is 60 s). |
| `SEEN_STORE_PATH` | no | Default `data/seen.json` locally, `/tmp/…` on serverless. |
| `CIRCUITS_DIR`, `PORT` | no | Artifact location override; local port (default 8787). |

No secrets are hardcoded anywhere; `.env` is gitignored and
`.env.example` ships blank values. The test harness uses a dummy
secret (`test-secret-do-not-use-in-production-…`) that only ever
signs test envelopes.

## Setup (local)

```bash
cd gatekeeper
npm install
npm run circuits        # re-download official artifacts (already present)
npm test                # boots the real server, replays all traps, verifies proofs
AGENT_GAMES_HMAC_SECRET=<platform secret> npm start   # listens on :8787
```

## Push to GitHub

Do this from Akmal's own machine/account (do not share credentials;
the agent never pushes). The repo must live under the **personal**
account `hitokamurashaki` — org-owned repos are not supported by
Agent Games.

```bash
cd ~/workspace/agent-games
git init
git add gatekeeper
git commit -m "Proof Gatekeeper agent: HMAC endpoint + Groth16 proofs"
git branch -M main
git remote add origin https://github.com/hitokamurashaki/agent-games.git
git push -u origin main
```

(`circuits/*.wasm` and `*.zkey` are gitignored — they are platform
artifacts; after cloning, run `npm install && npm run circuits` to
fetch them. `verification_key.json` + `circuit-info.json` are
committed.)

Repository URL to paste in the Agent Games form:
`https://github.com/hitokamurashaki/agent-games`

## Registration & preflight flow

1. **Register the account** at
   https://agentgames.zkverify.io/register — sign in with X
   (@wildbuddy88) or a wallet; pick a handle; connect GitHub
   (`hitokamurashaki`, required for prize eligibility) + wallet
   address (required before claiming prizes). One competition account
   per person; multi-account entry in the same event = disqualification.
2. **Register the agent** (dashboard → Register agent): select the
   **Proof Gatekeeper** track (Steal the VFY is also still selectable
   in the form, but see the Steal note below), paste the Repository
   URL above (required). **Agent Endpoint is optional at this step** —
   registration can proceed once the repo exists; the endpoint can be
   added after deploy.
3. **Deploy** (see below), then set the endpoint URL in the dashboard.
4. Dashboard → **Rotate Secret** → set the revealed plaintext as
   `AGENT_GAMES_HMAC_SECRET` → redeploy/restart. The secret is shown
   exactly once — store it securely, never commit it.
5. The platform sends a signed preflight
   (`type: agent-games.preflight.v1`); this agent answers
   `{ ok: true, protocolVersion: "v1" }` signed, and the dashboard
   marks the agent active. `GET /agent` also serves as the health check.
6. **Complete at least one practice task** before scored rounds
   (practice is capped at 10 dispatches/agent/hour and does not affect
   the leaderboard). Practice is where the remaining ambiguities get
   settled (see below).

## Deploy

The endpoint must be a **public HTTPS URL on the standard port** (no
localhost, no private IP, no custom ports). Register the full handler
path, e.g. `https://<host>/agent`, not the root.

Options (pick one; Akmal to confirm which host he has):

- **Long-lived VM/container (recommended):** `npm install && npm start`
  behind TLS (reverse proxy / Caddy / nginx). The seen-set lives in
  `data/seen.json`; a single long-lived instance keeps PROOF_REUSED
  detection reliable across all 8 rounds.
- **Vercel/Railway/Render:** works, but cold starts can reset the
  file-backed seen-set (memory still protects the process lifetime),
  and **free tiers that sleep after inactivity will forfeit tasks** —
  the platform's rule is explicit: offline when a task is delivered =
  forfeit that task. If using a free tier, add an external uptime
  pinger hitting `GET /agent` every few minutes, or use a paid
  always-on instance.

### Hosting notes

- Proof generation is ~0.3–1.3 s; total round-trip is far under 60 s.
- Keep exactly **one** instance serving the endpoint. Two instances
  would split the seen-set and could both approve the same proof.
- Never log the HMAC secret, a private key, or a seed phrase. Logs
  contain only task ids, decisions, and timings.

## Local test results

`npm test` boots the real server and replays spec-shaped envelopes.
Results are printed by the harness; the checks include:

- HMAC roundtrip, tamper / wrong-secret / missing signature → 401
- Preflight body shape + valid response signature; bad HMAC → 401
- Valid task → APPROVE / VALID_CONDITION, proof **verified locally**
  with `snarkjs groth16 verify` against the extracted verification key
- All six traps → correct REJECT + reason_code, each proof verified
  locally (PROOF_REUSED correctly carries no proof)
- Boundary cases: `balance == minimum` and `amount == max` → APPROVE
- Idempotent redelivery (cached response, not misread as reuse)
- Circuit referee: approving a trap and rejecting a valid condition
  both fail witness generation (unprovable by construction)
- Response times well under the 60 s deadline

## Spec ambiguities handled defensively

- **HMAC encoding:** /build mandates HMAC over the raw body but never
  names the algorithm/encoding. Outbound signing is HMAC-SHA256 hex;
  inbound verification accepts hex or base64 of the same MAC bytes
  (and an optional `sha256=` prefix), compared in constant time.
  Practice/preflight is the judge — if the platform rejects the
  signature, change one function (`src/hmac.js`).
- **Kurier / proof_tx:** the /build guide says to include the proof
  in the response; the event page's expected response shape lists
  `proof_tx`. This agent returns **both** (proof + public_signals,
  plus proof_tx when Kurier is configured). The Kurier integration
  itself is **not implemented** in this build: no key exists, no
  submission was ever made, and the exact Kurier endpoint paths were
  not confirmed from Kurier's own docs. `src/kurier.js` is a marked
  integration point. Practice mode will confirm whether the platform
  accepts proof+public_signals alone or requires a Kurier proof_tx —
  do not enable Kurier (or spend anything) before that is confirmed.
- **`INVALID_TASK`** is a local fallback reason code for
  envelope-level failures (malformed input, past deadline, internal
  error). It is outside the documented 7-code taxonomy and only
  reachable off the scored paths.
- **"Finalized before approval"** (Security checklist): the envelope
  carries no independently checkable finality proof for the
  referenced on-chain proof, so it is implemented as: our own proof
  is generated locally and (when Kurier is configured) submitted, with
  its on-chain `txHash` returned as `proof_tx`.

## Steal the VFY — status (do not build yet)

In the dashboard's Register agent form both tracks are still
selectable, and the endpoint field is optional — but that does **not**
mean Steal is enterable: entries lock once the tournament is paired
and a strategy commitment was required **before Swiss Round 1
(13 Nov)**. Verdict from the official pages: almost certainly too
late (~95% closed). The only way to settle the remaining ~5% is to
check the dashboard **after** registering. **Do not build the Steal
agent before that dashboard check.** If it turns out to be open, the
Steal circuit is `vfyPolicy` (`vkHash`
`0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`,
artifacts `vfy-policy.wasm` / `vfy-policy_final.zkey`); the strategy
commitment format is not publicly documented.

## Wildcard — same repo

If the Gatekeeper endpoint is live, the same repo can be submitted to
Wildcard before **21 Nov 2026** (public repo + endpoint + write-up,
panel-judged). No extra build work beyond this repo + a short write-up
of what the agent does.
