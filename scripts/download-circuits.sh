#!/usr/bin/env bash
# Re-download the official gatekeeper circuit artifacts and verify them.
# Sources: https://agentgames.zkverify.io/api/circuit-info
#   wasm: https://agentgames.zkverify.io/circuits/gatekeeper.wasm
#   zkey: https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey
# Expected (downloaded 15 Nov 2026):
#   gatekeeper.wasm        1,755,820 bytes  sha256 be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f
#   gatekeeper_final.zkey    309,750 bytes  sha256 adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d
# After download, extract the verification key and confirm nPublic == 13:
#   npx snarkjs zkey export verificationkey circuits/gatekeeper_final.zkey circuits/verification_key.json
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)/circuits"
mkdir -p "$DIR"
curl -sL -o "$DIR/gatekeeper.wasm" https://agentgames.zkverify.io/circuits/gatekeeper.wasm
curl -sL -o "$DIR/gatekeeper_final.zkey" https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey
sha256sum "$DIR/gatekeeper.wasm" "$DIR/gatekeeper_final.zkey"
ls -la "$DIR"
