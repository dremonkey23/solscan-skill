# SolScan - Solana Smart Contract Auditor

> Audit Solana programs before you ship. Find vulnerabilities before attackers do.
> *by cybersecurity experts*

## What This Skill Does

SolScan performs static analysis on Solana smart contracts written in Rust (native or Anchor framework). It scans for the most common and dangerous vulnerability patterns that have caused real losses on Solana, outputs severity-graded findings, and explains how to fix each one.

**This is a preliminary audit tool.** It catches common patterns automatically. It does not replace a full manual audit for high-value programs.

## How to Run It

1. Detect the OS
2. Get the contract code (file path or pasted code saved to temp file)
3. Run the appropriate script
4. Parse and present the output

### Run the script

**Windows (PowerShell):**
```powershell
powershell -ExecutionPolicy Bypass -File scan-contract.ps1 -Path "C:\path\to\contract.rs"
```

**Mac/Linux (bash):**
```bash
bash scan-contract.sh /path/to/contract.rs
```

Pass either:
- A `.rs` file path
- A directory (scans all `.rs` files recursively)

## Vulnerability Categories

### Critical
- **Missing signer check** — instruction can be called by anyone
- **Missing owner check** — account ownership not validated
- **Arbitrary CPI** — calling untrusted programs without validation
- **Lamport drain** — SOL balance can be drained from accounts

### High
- **Integer overflow** — unchecked arithmetic on token amounts
- **Missing account validation** — accounts not validated before use
- **Unchecked return values** — CPI results not checked
- **Insecure PDA derivation** — predictable or manipulable seeds

### Medium
- **Reentrancy via CPI** — state not updated before CPI call
- **Timestamp dependence** — using Clock::get() for critical logic
- **Missing rent exemption check** — accounts may be garbage collected
- **Unrestricted account closing** — close constraint without security check

### Low
- **Todo/fixme comments** — unfinished security logic
- **Missing event emission** — no audit trail for critical operations
- **Hardcoded program IDs** — inflexible and potentially risky

## Output Format

Present exactly like this:

```
SolScan Report -- program.rs
-----------------------------------
Scanning 3 files...

[CRITICAL] (2)
  * Missing signer check in process_withdraw (line 45) - anyone can call this instruction
  * Arbitrary CPI in invoke_program (line 89) - validate program ID before invoking

[HIGH] (1)
  * Unchecked arithmetic in calculate_rewards (line 112) - use checked_add/checked_mul

[MEDIUM] (0)

[LOW] (1)
  * TODO comment in validate_accounts (line 23) - unfinished security logic

PASSED:
  * Owner checks present on critical accounts
  * Rent exemption handled correctly

Top Fix:
-> Add `require!(ctx.accounts.authority.is_signer, ErrorCode::Unauthorized);`
-> Validate CPI target: `require_keys_eq!(program.key(), EXPECTED_PROGRAM_ID)`

-----------------------------------
by cybersecurity experts | SolScan v1.0
```

## Remediation Reference

**Missing signer check fix:**
```rust
require!(ctx.accounts.authority.is_signer, ErrorCode::Unauthorized);
```

**Integer overflow fix:**
```rust
// Instead of: amount + fee
let total = amount.checked_add(fee).ok_or(ErrorCode::Overflow)?;
```

**Arbitrary CPI fix:**
```rust
require_keys_eq!(
    cpi_program.key(),
    expected_program::ID,
    ErrorCode::InvalidProgram
);
```

**Missing owner check fix:**
```rust
require_keys_eq!(
    account.owner,
    expected_program::ID,
    ErrorCode::InvalidOwner
);
```
