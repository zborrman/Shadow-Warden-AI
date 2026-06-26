#!/usr/bin/env bash
# PreToolUse hook: blocks dangerous Bash commands before Claude executes them.
# Reads tool event JSON from stdin; exits 1 to block, 0 to allow.
python3 - <<'PYEOF'
import sys, json, re

try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)  # fail-open on parse error

cmd = d.get("tool_input", {}).get("command", "")

BLOCKED_PATTERNS = [
    r"rm\s+-rf\s+/(?!tmp)",              # rm -rf / (but allow /tmp)
    r"git\s+push\s+--force\s+origin\s+main",  # force-push to main
    r"git\s+reset\s+--hard\s+origin",    # hard reset to remote
    r"DROP\s+TABLE\s+(?!IF)",            # DROP TABLE without IF EXISTS
    r"docker\s+rm\s+-f\s+warden",        # force-remove warden container
    r"pkill\s+-9\s+python",              # kill all python processes
    r"truncate\s+--size\s+0\s+/opt",     # truncate production files
    r">\s*/opt/shadow-warden/\.env",     # overwrite production .env
]

for pattern in BLOCKED_PATTERNS:
    if re.search(pattern, cmd, re.IGNORECASE):
        print(f"BLOCKED: matched pattern [{pattern}]", file=sys.stderr)
        sys.exit(1)

sys.exit(0)
PYEOF
