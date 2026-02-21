param(
    [Parameter(Mandatory=$true)]
    [string]$Path
)

if (-not (Test-Path $Path)) {
    Write-Error "Path not found: $Path"
    exit 1
}

$findings_critical = [System.Collections.Generic.List[string]]::new()
$findings_high     = [System.Collections.Generic.List[string]]::new()
$findings_medium   = [System.Collections.Generic.List[string]]::new()
$findings_low      = [System.Collections.Generic.List[string]]::new()
$passed            = [System.Collections.Generic.List[string]]::new()

# Collect .rs files
if ((Get-Item $Path).PSIsContainer) {
    $files = Get-ChildItem -Path $Path -Recurse -Filter "*.rs" -ErrorAction SilentlyContinue
} else {
    $files = @(Get-Item $Path)
}

Write-Host ""
Write-Host "SolScan Report -- $Path"
Write-Host "-----------------------------------"
Write-Host "Scanning $($files.Count) Rust file(s)..."
Write-Host ""

# Tracking flags for PASSED checks
$hasSignerCheck   = $false
$hasOwnerCheck    = $false
$hasCheckedMath   = $false
$hasRentCheck     = $false

foreach ($file in $files) {
    $relPath = $file.Name
    $lines   = Get-Content $file.FullName -ErrorAction SilentlyContinue
    if (-not $lines) { continue }

    $lineNum = 0
    # Function/instruction context tracking
    $currentFn = ""

    foreach ($line in $lines) {
        $lineNum++
        $trimmed = $line.Trim()

        # Track current function name
        if ($trimmed -match 'pub fn ([a-zA-Z_][a-zA-Z0-9_]*)') {
            $currentFn = $Matches[1]
        }

        # ---- CRITICAL ----

        # Missing signer check: instruction functions that use ctx but no is_signer
        # Flag process_/withdraw_/transfer_ functions without require!(*.is_signer
        if ($trimmed -match 'pub fn (process_|withdraw|transfer|mint|burn|close|update|initialize)' -and
            $trimmed -notmatch 'is_signer') {
            $fnName = if ($Matches[1]) { $Matches[1] } else { "unknown" }
            $findings_critical.Add("Possible missing signer check near '$trimmed' in $relPath (line $lineNum) - verify is_signer validation exists")
        }

        # Detect is_signer usage (positive signal)
        if ($trimmed -match '\.is_signer') {
            $hasSignerCheck = $true
        }

        # Arbitrary CPI - invoke without program ID validation
        if ($trimmed -match '\binvoke\s*\(' -and $trimmed -notmatch 'require_keys_eq|key\(\)\s*==') {
            $findings_critical.Add("Unchecked CPI call in $relPath (line $lineNum) - validate program ID before invoke()")
        }

        # Lamport drain pattern
        if ($trimmed -match 'lamports.*=.*0' -or ($trimmed -match 'lamports' -and $trimmed -match '\*\*from_account\b')) {
            $findings_critical.Add("Potential lamport drain pattern in $relPath (line $lineNum) - verify account balance protection")
        }

        # ---- HIGH ----

        # Unchecked arithmetic
        if ($trimmed -match '\b(amount|balance|price|fee|reward|supply)\s*[\+\-\*]' -and
            $trimmed -notmatch 'checked_add|checked_sub|checked_mul|checked_div|saturating_') {
            $findings_high.Add("Unchecked arithmetic on '$($Matches[0].Trim())' in $relPath (line $lineNum) - use checked_add/checked_sub/checked_mul")
        } else {
            if ($trimmed -match 'checked_add|checked_sub|checked_mul') { $hasCheckedMath = $true }
        }

        # Missing owner check
        if ($trimmed -match '\.owner' -and $trimmed -notmatch 'require_keys_eq|==|!=') {
            $findings_high.Add("Possible unchecked owner access in $relPath (line $lineNum) - validate account owner")
        }

        # Detect owner check (positive signal)
        if ($trimmed -match 'require_keys_eq.*owner|owner.*==|has_one\s*=') {
            $hasOwnerCheck = $true
        }

        # Unchecked return value from CPI
        if ($trimmed -match 'invoke\s*\(' -and $trimmed -notmatch '\?' -and $trimmed -notmatch 'let\s+.*=') {
            $findings_high.Add("Unchecked CPI return value in $relPath (line $lineNum) - use ? operator or handle error")
        }

        # ---- MEDIUM ----

        # Reentrancy - state mutation after CPI
        if ($trimmed -match 'invoke\s*\(' -and $lineNum -gt 1) {
            # Check next few lines for state changes (heuristic)
            $nextLines = $lines[$lineNum..([Math]::Min($lineNum+3, $lines.Count-1))]
            foreach ($nl in $nextLines) {
                if ($nl -match 'ctx\.accounts\.\w+\.\w+\s*=') {
                    $findings_medium.Add("Possible reentrancy - state modified after CPI in $relPath (near line $lineNum) - update state before CPI calls")
                    break
                }
            }
        }

        # Clock/timestamp dependence
        if ($trimmed -match 'Clock::get\(\)' -and $currentFn -match 'transfer|withdraw|reward|vesting|unlock') {
            $findings_medium.Add("Timestamp dependence in $currentFn in $relPath (line $lineNum) - avoid using clock for critical logic")
        }

        # Missing rent exemption
        if ($trimmed -match 'create_account|init' -and $trimmed -notmatch 'rent.*exempt|minimum_balance') {
            $hasRentCheck = $false
        } else {
            if ($trimmed -match 'rent.*exempt|minimum_balance') { $hasRentCheck = $true }
        }

        # Unchecked account closing
        if ($trimmed -match 'close\s*=\s*' -and $trimmed -notmatch 'constraint|require') {
            $findings_medium.Add("Unchecked account close in $relPath (line $lineNum) - add constraint to validate close authority")
        }

        # ---- LOW ----

        # TODO / FIXME in security-sensitive context
        if ($trimmed -match '//\s*(TODO|FIXME|HACK|XXX)' -and
            ($currentFn -match 'validate|check|verify|auth|sign|owner|transfer|withdraw' -or
             $trimmed -match 'security|auth|signer|owner|permission')) {
            $findings_low.Add("$($Matches[1]) comment in security context - $relPath (line $lineNum): $trimmed")
        }

        # Hardcoded program IDs
        if ($trimmed -match '"[1-9A-HJ-NP-Za-km-z]{32,44}"' -and $trimmed -notmatch '//') {
            $findings_low.Add("Hardcoded address/ID in $relPath (line $lineNum) - consider using declared_id! or constants")
        }

        # Missing event emission on critical ops
        if ($trimmed -match 'pub fn (withdraw|transfer|mint|burn)' -and $trimmed -notmatch 'emit!') {
            $fnName = $Matches[1]
            $findings_low.Add("No emit!() found near $fnName in $relPath (line $lineNum) - consider emitting events for audit trail")
        }
    }
}

# PASSED checks
if ($hasSignerCheck)              { $passed.Add("Signer checks (is_signer) found in codebase") }
if ($hasOwnerCheck)               { $passed.Add("Owner validation found in codebase") }
if ($hasCheckedMath)              { $passed.Add("Checked arithmetic (checked_add/sub/mul) in use") }
if ($files.Count -gt 0 -and $findings_critical.Count -eq 0) { $passed.Add("No critical vulnerabilities detected") }

# Report
$hasSomething = $false

if ($findings_critical.Count -gt 0) {
    $hasSomething = $true
    Write-Host "[CRITICAL] ($($findings_critical.Count))"
    foreach ($f in $findings_critical) { Write-Host "  * $f" }
    Write-Host ""
}

if ($findings_high.Count -gt 0) {
    $hasSomething = $true
    Write-Host "[HIGH] ($($findings_high.Count))"
    foreach ($f in $findings_high) { Write-Host "  * $f" }
    Write-Host ""
}

if ($findings_medium.Count -gt 0) {
    $hasSomething = $true
    Write-Host "[MEDIUM] ($($findings_medium.Count))"
    foreach ($f in $findings_medium) { Write-Host "  * $f" }
    Write-Host ""
}

if ($findings_low.Count -gt 0) {
    $hasSomething = $true
    Write-Host "[LOW] ($($findings_low.Count))"
    foreach ($f in $findings_low) { Write-Host "  * $f" }
    Write-Host ""
}

if (-not $hasSomething) {
    Write-Host "No vulnerabilities detected in $($files.Count) file(s)."
    Write-Host ""
}

if ($passed.Count -gt 0) {
    Write-Host "PASSED:"
    foreach ($p in $passed) { Write-Host "  * $p" }
    Write-Host ""
}

# Top 2 fixes
$allFindings = @($findings_critical) + @($findings_high)
if ($allFindings.Count -gt 0) {
    Write-Host "Top Fix:"
    $allFindings | Select-Object -First 2 | ForEach-Object { Write-Host "-> $_" }
    Write-Host ""
}

Write-Host "-----------------------------------"
Write-Host "by cybersecurity experts | SolScan v1.0"
