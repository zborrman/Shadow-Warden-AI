#!/usr/bin/env bash
#
# Compile contracts/Escrow.sol and refresh the ABI + bytecode.
#
# solc runs in Docker so the toolchain is pinned and nobody has to install it:
# a contract compiled by whatever solc happened to be on someone's laptop is not
# reproducible, and reproducibility is the only way an operator can check that
# the deployed bytecode came from the source in this repository.
#
#   bash scripts/build_escrow.sh
#
# Writes contracts/escrow.abi.json and contracts/escrow.bin. Commit both, and
# state the solc version in the PR — the deployed address is verified against
# that pair on the block explorer, not against the .sol file.
set -euo pipefail

SOLC_VERSION="${SOLC_VERSION:-0.8.24}"
cd "$(dirname "$0")/.."

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required (solc runs in a pinned container)" >&2
  exit 1
fi

echo "compiling contracts/Escrow.sol with solc ${SOLC_VERSION}"
docker run --rm -v "$PWD/contracts:/src" "ethereum/solc:${SOLC_VERSION}" \
  --optimize --optimize-runs 200 --combined-json abi,bin /src/Escrow.sol \
  > contracts/.solc-out.json

python3 - <<'PY'
import json, pathlib
out = json.loads(pathlib.Path("contracts/.solc-out.json").read_text())
key = next(k for k in out["contracts"] if k.endswith(":Escrow"))
entry = out["contracts"][key]
abi = entry["abi"]
abi = json.loads(abi) if isinstance(abi, str) else abi
pathlib.Path("contracts/escrow.abi.json").write_text(json.dumps(abi, indent=2) + "\n")
pathlib.Path("contracts/escrow.bin").write_text(entry["bin"] + "\n")
print(f"wrote contracts/escrow.abi.json ({len(abi)} entries) and contracts/escrow.bin")
PY

rm -f contracts/.solc-out.json
echo "now re-run: pytest warden/tests/test_escrow_abi_matches_callers.py"
