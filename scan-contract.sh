#!/bin/bash
# SolScan - Solana Smart Contract Auditor (Mac/Linux)

if [ -z "$1" ]; then
    echo "Usage: bash scan-contract.sh <path-to-contract.rs or directory>"
    exit 1
fi

PATH_ARG="$1"

if [ ! -e "$PATH_ARG" ]; then
    echo "Error: Path not found: $PATH_ARG"
    exit 1
fi

# Collect files
if [ -d "$PATH_ARG" ]; then
    FILES=$(find "$PATH_ARG" -name "*.rs" 2>/dev/null)
else
    FILES="$PATH_ARG"
fi

FILE_COUNT=$(echo "$FILES" | grep -c "\.rs" 2>/dev/null || echo "0")

echo ""
echo "SolScan Report -- $PATH_ARG"
echo "-----------------------------------"
echo "Scanning $FILE_COUNT Rust file(s)..."
echo ""

CRITICAL=()
HIGH=()
MEDIUM=()
LOW=()
PASSED=()

HAS_SIGNER=false
HAS_OWNER=false
HAS_CHECKED_MATH=false

while IFS= read -r FILE; do
    [ -z "$FILE" ] && continue
    RELPATH=$(basename "$FILE")
    LINENUM=0
    CURRENT_FN=""

    while IFS= read -r LINE; do
        LINENUM=$((LINENUM + 1))
        TRIMMED=$(echo "$LINE" | sed 's/^[[:space:]]*//')

        # Track function name
        if echo "$TRIMMED" | grep -qE 'pub fn ([a-zA-Z_][a-zA-Z0-9_]*)'; then
            CURRENT_FN=$(echo "$TRIMMED" | grep -oE 'pub fn [a-zA-Z_][a-zA-Z0-9_]*' | awk '{print $3}')
        fi

        # CRITICAL: Missing signer check
        if echo "$TRIMMED" | grep -qE 'pub fn (process_|withdraw|transfer|mint|burn|close|update|initialize)'; then
            if ! echo "$TRIMMED" | grep -q 'is_signer'; then
                FN_NAME=$(echo "$TRIMMED" | grep -oE '(process_|withdraw|transfer|mint|burn|close|update|initialize)[a-zA-Z_0-9]*')
                CRITICAL+=("Possible missing signer check near '$FN_NAME' in $RELPATH (line $LINENUM) - verify is_signer validation exists")
            fi
        fi

        if echo "$TRIMMED" | grep -q '\.is_signer'; then
            HAS_SIGNER=true
        fi

        # CRITICAL: Arbitrary CPI
        if echo "$TRIMMED" | grep -qE '\binvoke\s*\('; then
            if ! echo "$TRIMMED" | grep -qE 'require_keys_eq|key\(\)\s*=='; then
                CRITICAL+=("Unchecked CPI call in $RELPATH (line $LINENUM) - validate program ID before invoke()")
            fi
        fi

        # CRITICAL: Lamport drain
        if echo "$TRIMMED" | grep -qE 'lamports.*=.*0|\*\*from_account'; then
            CRITICAL+=("Potential lamport drain pattern in $RELPATH (line $LINENUM) - verify account balance protection")
        fi

        # HIGH: Unchecked arithmetic
        if echo "$TRIMMED" | grep -qE '\b(amount|balance|price|fee|reward|supply)\s*[\+\-\*]'; then
            if ! echo "$TRIMMED" | grep -qE 'checked_add|checked_sub|checked_mul|saturating_'; then
                HIGH+=("Unchecked arithmetic in $RELPATH (line $LINENUM) - use checked_add/checked_sub/checked_mul")
            else
                HAS_CHECKED_MATH=true
            fi
        fi

        if echo "$TRIMMED" | grep -qE 'checked_add|checked_sub|checked_mul'; then
            HAS_CHECKED_MATH=true
        fi

        # HIGH: Owner check
        if echo "$TRIMMED" | grep -q '\.owner'; then
            if ! echo "$TRIMMED" | grep -qE 'require_keys_eq|==|!=|has_one'; then
                HIGH+=("Possible unchecked owner access in $RELPATH (line $LINENUM) - validate account owner")
            fi
        fi

        if echo "$TRIMMED" | grep -qE 'require_keys_eq.*owner|has_one\s*='; then
            HAS_OWNER=true
        fi

        # MEDIUM: Timestamp dependence
        if echo "$TRIMMED" | grep -q 'Clock::get()'; then
            if echo "$CURRENT_FN" | grep -qE 'transfer|withdraw|reward|vesting|unlock'; then
                MEDIUM+=("Timestamp dependence in $CURRENT_FN in $RELPATH (line $LINENUM) - avoid clock for critical logic")
            fi
        fi

        # MEDIUM: Unchecked account closing
        if echo "$TRIMMED" | grep -qE 'close\s*='; then
            if ! echo "$TRIMMED" | grep -qE 'constraint|require'; then
                MEDIUM+=("Unchecked account close in $RELPATH (line $LINENUM) - add constraint to validate close authority")
            fi
        fi

        # LOW: TODO/FIXME in security context
        if echo "$TRIMMED" | grep -qiE '//\s*(TODO|FIXME|HACK)'; then
            if echo "$TRIMMED$CURRENT_FN" | grep -qiE 'security|auth|signer|owner|permission|validate|verify'; then
                TAG=$(echo "$TRIMMED" | grep -oiE '(TODO|FIXME|HACK)')
                LOW+=("$TAG in security context in $RELPATH (line $LINENUM)")
            fi
        fi

        # LOW: Hardcoded addresses
        if echo "$TRIMMED" | grep -qE '"[1-9A-HJ-NP-Za-km-z]{32,44}"'; then
            if ! echo "$TRIMMED" | grep -q '//'; then
                LOW+=("Hardcoded Solana address in $RELPATH (line $LINENUM) - use declared_id! or constants")
            fi
        fi

    done < "$FILE"
done <<< "$FILES"

# PASSED signals
$HAS_SIGNER && PASSED+=("Signer checks (is_signer) found in codebase")
$HAS_OWNER  && PASSED+=("Owner validation found in codebase")
$HAS_CHECKED_MATH && PASSED+=("Checked arithmetic in use")
[ ${#CRITICAL[@]} -eq 0 ] && PASSED+=("No critical vulnerabilities detected")

# Print report
HAS_SOMETHING=false

if [ ${#CRITICAL[@]} -gt 0 ]; then
    HAS_SOMETHING=true
    echo "[CRITICAL] (${#CRITICAL[@]})"
    for f in "${CRITICAL[@]}"; do echo "  * $f"; done
    echo ""
fi

if [ ${#HIGH[@]} -gt 0 ]; then
    HAS_SOMETHING=true
    echo "[HIGH] (${#HIGH[@]})"
    for f in "${HIGH[@]}"; do echo "  * $f"; done
    echo ""
fi

if [ ${#MEDIUM[@]} -gt 0 ]; then
    HAS_SOMETHING=true
    echo "[MEDIUM] (${#MEDIUM[@]})"
    for f in "${MEDIUM[@]}"; do echo "  * $f"; done
    echo ""
fi

if [ ${#LOW[@]} -gt 0 ]; then
    HAS_SOMETHING=true
    echo "[LOW] (${#LOW[@]})"
    for f in "${LOW[@]}"; do echo "  * $f"; done
    echo ""
fi

if [ "$HAS_SOMETHING" = "false" ]; then
    echo "No vulnerabilities detected."
    echo ""
fi

if [ ${#PASSED[@]} -gt 0 ]; then
    echo "PASSED:"
    for p in "${PASSED[@]}"; do echo "  * $p"; done
    echo ""
fi

echo "-----------------------------------"
echo "by cybersecurity experts | SolScan v1.0"
