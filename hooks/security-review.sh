#!/usr/bin/env bash
# hooks/security-review.sh — OWASP MCP Top 10 pre-deployment security gate
#
# Checks staged git changes for patterns indicative of:
#   MCP-01 Tool Poisoning         — unsanitized tool input passed to shell/eval
#   MCP-02 Command Injection      — shell metacharacters in dynamic commands
#   MCP-03 Scope Creep            — excessive permissions / broad * wildcards
#   MCP-04 Prompt Injection       — system prompt overrides in tool args
#   MCP-05 Indirect Prompt Inj.  — user content injected into system prompt
#   MCP-06 Insecure Data Exposure — secrets/keys in code or logs
#   MCP-07 Excessive Agency       — autonomous destructive ops without approval
#   MCP-08 Unintended Persistence — unbounded Redis/DB writes per-request
#   MCP-09 Insecure Tool Chaining — tool output used without validation
#   MCP-10 Inadequate Logging     — missing audit trail on sensitive operations
#
# Exit 0 = pass, Exit 1 = violations found (blocks deployment)
# Run manually: bash hooks/security-review.sh [path/to/diff.patch]

set -euo pipefail

RED='\033[0;31m'
YLW='\033[1;33m'
GRN='\033[0;32m'
NC='\033[0m'

VIOLATIONS=0
WARNINGS=0
LOG_FILE="${HOME}/.claude/logs/security_review.log"
mkdir -p "$(dirname "$LOG_FILE")"

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" >> "$LOG_FILE"; }
fail() { echo -e "${RED}[FAIL MCP-$1]${NC} $2"; VIOLATIONS=$((VIOLATIONS+1)); log "FAIL MCP-$1: $2"; }
warn() { echo -e "${YLW}[WARN MCP-$1]${NC} $2"; WARNINGS=$((WARNINGS+1));  log "WARN MCP-$1: $2"; }

# Get staged diff or use provided path
if [[ "${1:-}" == *.patch ]]; then
    DIFF=$(cat "$1")
else
    DIFF=$(git diff --cached -- '*.py' '*.ts' '*.tsx' '*.sh' 2>/dev/null || echo "")
fi

if [[ -z "$DIFF" ]]; then
    echo -e "${GRN}[SKIP]${NC} No staged Python/TS/shell changes — security review skipped."
    exit 0
fi

echo "=== OWASP MCP Top 10 Security Review ==="
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) | staged changes"
echo ""

# MCP-01: Tool Poisoning — eval/exec on tool arguments
if echo "$DIFF" | grep -qP '^\+.*\b(eval|exec)\s*\((?!#)'; then
    fail "01" "eval/exec called on potentially tool-supplied input"
fi

# MCP-02: Command Injection — shell=True with variable interpolation
if echo "$DIFF" | grep -qP '^\+.*subprocess\.(run|call|Popen|check_output).*shell\s*=\s*True.*f["\']'; then
    fail "02" "subprocess with shell=True and f-string — command injection risk"
fi
if echo "$DIFF" | grep -qP '^\+.*os\.system\s*\('; then
    warn "02" "os.system() found — prefer subprocess with shell=False"
fi

# MCP-03: Scope Creep — overly broad permissions or wildcard tool access
if echo "$DIFF" | grep -qP '^\+.*"allow"\s*:\s*\[.*"\*"'; then
    fail "03" "Wildcard (*) in allow list — excessive permission grant"
fi
if echo "$DIFF" | grep -qP '^\+.*permissions.*all_tools|allow_all|unrestricted'; then
    warn "03" "Broad permission keyword detected — review tool scope"
fi

# MCP-04 / MCP-05: Prompt Injection — user content in system role
if echo "$DIFF" | grep -qP '^\+.*"role"\s*:\s*"system".*\{[a-z_]+\}'; then
    fail "04" "User variable interpolated into system prompt — prompt injection risk"
fi
if echo "$DIFF" | grep -qP '^\+.*system_prompt.*f["\'].*\{(user|input|query|message|content)\}'; then
    fail "05" "User-controlled content injected into system_prompt f-string"
fi

# MCP-06: Insecure Data Exposure — hardcoded secrets or keys
if echo "$DIFF" | grep -qP '^\+.*(api_key|secret_key|password|token)\s*=\s*["\'][A-Za-z0-9+/]{20,}'; then
    fail "06" "Potential hardcoded credential detected"
fi
if echo "$DIFF" | grep -qP '^\+.*log\.(info|debug|warning)\(.*\b(key|secret|password|token)\b'; then
    warn "06" "Sensitive field name appears in log statement — verify no plaintext"
fi

# MCP-07: Excessive Agency — destructive ops without REQUIRES_APPROVAL flag
if echo "$DIFF" | grep -qP '^\+.*(delete_all|drop_table|rm -rf|shutil\.rmtree|git push --force)'; then
    if ! echo "$DIFF" | grep -qP 'REQUIRES_APPROVAL|require_approval|approval_gate'; then
        fail "07" "Destructive operation without approval gate"
    fi
fi

# MCP-08: Unintended Persistence — unbounded Redis LPUSH without LTRIM
if echo "$DIFF" | grep -qP '^\+.*redis.*lpush' && ! echo "$DIFF" | grep -qP '^\+.*redis.*ltrim'; then
    warn "08" "LPUSH without LTRIM — unbounded list growth risk"
fi

# MCP-09: Insecure Tool Chaining — tool output used directly in SQL/shell
if echo "$DIFF" | grep -qP '^\+.*execute\s*\(.*tool_result|tool_output'; then
    fail "09" "Tool output passed directly to DB execute() — SQL injection risk"
fi

# MCP-10: Inadequate Logging — sensitive route without audit log call
PY_ROUTES=$(echo "$DIFF" | grep -P '^\+.*@router\.(post|delete|patch)\s*\(' | wc -l)
PY_AUDITS=$(echo "$DIFF" | grep -P '^\+.*(audit_log|log_event|append_transfer|log\.info)' | wc -l)
if [[ "$PY_ROUTES" -gt 0 && "$PY_AUDITS" -eq 0 ]]; then
    warn "10" "$PY_ROUTES new POST/DELETE/PATCH routes with no audit log calls detected"
fi

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo "=== Results ==="
echo "Violations (blocking):  $VIOLATIONS"
echo "Warnings (advisory):    $WARNINGS"
log "SUMMARY violations=$VIOLATIONS warnings=$WARNINGS"

if [[ "$VIOLATIONS" -gt 0 ]]; then
    echo -e "\n${RED}Security review FAILED — $VIOLATIONS blocking violation(s).${NC}"
    echo "Fix the issues above before deploying to production."
    exit 1
else
    echo -e "\n${GRN}Security review PASSED.${NC}"
    exit 0
fi
