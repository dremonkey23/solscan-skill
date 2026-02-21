# SolScan

**Audit Solana programs before you ship. Find vulnerabilities before attackers do.**
*by @drizzy8423*

---

SolScan performs static analysis on Solana smart contracts written in Rust. It scans for the exact vulnerability patterns that have caused millions in losses on Solana — reentrancy, missing signer checks, unchecked arithmetic, arbitrary CPIs, and more.

Point it at any `.rs` file or directory. Get a severity-graded report with plain-English fixes in seconds.

## What It Checks

| Severity | Vulnerability |
|---|---|
| CRITICAL | Missing signer checks (anyone can call your instruction) |
| CRITICAL | Arbitrary CPI (calling untrusted programs without validation) |
| CRITICAL | Lamport drain patterns (SOL balance attacks) |
| HIGH | Unchecked arithmetic (overflow/underflow on token amounts) |
| HIGH | Missing owner/account validation |
| HIGH | Unchecked CPI return values |
| MEDIUM | Reentrancy via CPI (state mutation after invoke) |
| MEDIUM | Timestamp dependence (Clock::get() in critical logic) |
| MEDIUM | Unchecked account closing |
| LOW | TODO/FIXME in security-sensitive functions |
| LOW | Hardcoded program IDs and addresses |
| LOW | Missing event emission on critical operations |

Works with native Rust programs and Anchor framework.

## Sample Output

```
SolScan Report -- vault.rs
-----------------------------------
Scanning 1 Rust file(s)...

[CRITICAL] (2)
  * Missing signer check near withdraw in vault.rs (line 10)
  * Unchecked CPI call in vault.rs (line 23) - validate program ID

[HIGH] (1)
  * Unchecked arithmetic on balance in vault.rs (line 14)

PASSED:
  * Owner validation found in codebase
  * Checked arithmetic in use

Top Fix:
-> Add: require!(ctx.accounts.authority.is_signer, ErrorCode::Unauthorized);
-> Validate CPI: require_keys_eq!(program.key(), EXPECTED_PROGRAM_ID)

-----------------------------------
by @drizzy8423 | SolScan v1.0
```

## How to Use

Just tell your OpenClaw agent:

> "Scan this Solana contract for vulnerabilities" + paste the code or file path

SolScan handles the rest.

## Platform Support

- Windows (PowerShell)
- macOS (bash)
- Linux (bash)

## Disclaimer

SolScan is a static analysis tool. It catches common vulnerability patterns automatically. It does not replace a full manual audit for high-value programs. Always get a professional audit before deploying contracts that hold significant value.

---

*SolScan v1.0 — by @drizzy8423*
