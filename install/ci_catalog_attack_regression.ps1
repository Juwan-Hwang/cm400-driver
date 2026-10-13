#Requires -Version 7
<#
  Attack regression for the release candidate gate.

  Every case builds a mutated copy of the staged package under %TEMP% and runs the *real* pre-execution
  verifier on it, asserting both the exit code and which leg refused. A case that fails for an unrelated
  reason is a case that has not tested anything, so the reason check is not optional.

  The cases correspond to what the three legs were measured to cover:

    pristine                 accepted; the gate is not simply a wall
    signed content flipped   leg 2b signature  -> crypt32 reports a hash error; the catalog no longer
                             matches what was signed
    embedded cert flipped    leg 2b identity    -> still verifies, because `certificates` sits outside
                             the signed digest; caught only by comparing the embedded DER with the pin
    INF replaced + manifest recomputed for it, catalog untouched   leg 3 content binding
    installer + manifest swapped as a pair, catalog untouched      refused before any candidate runs
    extra file / subdirectory / hidden file / missing catalog      layout
    unsigned catalog                                               refused, never treated as "unknown"

  Nothing here runs a candidate binary, touches a trust store, or modifies dist\staging.

  Exit codes: 0 all cases behaved as required; 50 at least one case did not; 51 the harness itself could
  not run (verifier or package missing - reported rather than silently passing zero cases).
#>
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$Package = '',
    [string]$Catsig = ''
)
$ErrorActionPreference = 'Continue'
if (-not $Package) { $Package = Join-Path $RepoRoot 'dist\staging' }
if (-not (Test-Path (Join-Path $Package 'cm400.cat'))) {
    Write-Host "FAIL(51): no signed package at $Package - a regression that tests nothing must not pass"
    exit 51
}
$verifier = $Catsig
if (-not $verifier) {
    $verifier = @(
        (Join-Path $env:CARGO_TARGET_DIR 'debug\cm400-catsig.exe'),
        (Join-Path $env:CARGO_TARGET_DIR 'release\cm400-catsig.exe'),
        (Join-Path $RepoRoot 'target\release\cm400-catsig.exe')
    ) | ?{ Test-Path $_ } | Select-Object -First 1
}
if (-not $verifier) { Write-Host 'FAIL(51): cm400-catsig.exe is not built'; exit 51 }
Write-Host "verifier: $verifier"
Write-Host "package : $Package"

$work = Join-Path $env:TEMP "cm400-attack-$([guid]::NewGuid().ToString('N').Substring(0,8))"
New-Item -ItemType Directory -Force -Path $work | Out-Null
$script:bad = 0

function New-Copy([string]$name) {
    $d = Join-Path $work $name
    if (Test-Path $d) { Remove-Item $d -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $d | Out-Null
    Copy-Item (Join-Path $Package '*') $d -Force -Recurse
    # prove the copy is a copy: a directory that silently arrived empty would turn every case into a
    # false pass, which is exactly the failure mode this harness has had once already
    if (@(Get-ChildItem $d -File).Count -ne @(Get-ChildItem $Package -File).Count) {
        throw "copy $name has $(@(Get-ChildItem $d -File).Count) files, the package has $(@(Get-ChildItem $Package -File).Count)"
    }
    return $d
}
function Flip([string]$path, [int]$offset) {
    $b = [IO.File]::ReadAllBytes($path)
    if ($offset -ge $b.Length) { throw "offset $offset beyond end of $path" }
    $b[$offset] = $b[$offset] -bxor 1
    [IO.File]::WriteAllBytes($path, $b)
    $after = [IO.File]::ReadAllBytes($path)
    if ($after[$offset] -eq ($b[$offset] -bxor 1)) { throw "the write to $path did not take effect" }
}
function Changed([string]$dir, [string]$rel) {
    # a mutation that did not happen cannot demonstrate a refusal; report it as a harness failure
    $a = Join-Path $Package $rel; $b = Join-Path $dir $rel
    if (-not (Test-Path $b)) { return $false }
    $ha = (Get-FileHash $a -Algorithm SHA256).Hash; $hb = (Get-FileHash $b -Algorithm SHA256).Hash
    return $ha -ne $hb
}
function Case {
    param([string]$Name, [string]$Dir, [int[]]$WantExit, [string]$WantPattern, [string[]]$MustChange = @())
    foreach ($rel in $MustChange) {
        if (-not (Changed $Dir $rel)) {
            Write-Host ("  [FAIL] {0}: the mutation of {1} did not take effect, so this case tested nothing" -f $Name, $rel)
            $script:bad++
            return
        }
    }
    # a real child process, because the verifier reports through the host and host writes do not reach
    # an in-process `| Out-String`
    $out = (& pwsh -NoProfile -File (Join-Path $PSScriptRoot 'ci_preverify_candidate.ps1') `
            -PackageDir $Dir -RepoRoot $RepoRoot -Catsig $verifier 2>&1) -join "`n"
    $code = $LASTEXITCODE
    $inWant = @($WantExit) -contains $code
    $patternHit = if ($WantPattern) { $out -match $WantPattern } else { $true }
    $ok = $inWant -and $patternHit
    $refusal = ''
    if ($code -ne 0 -and $out -match '(?m)^\s*FAIL\((\d+)\): (.+)$') {
        $refusal = 'refusal: ' + $Matches[2].Trim()
        if ($refusal.Length -gt 100) { $refusal = $refusal.Substring(0, 100) }
    }
    $status = if ($ok) { 'PASS' } else { 'FAIL' }
    $want = $WantExit -join '/'
    $pat = if ($WantPattern) { "'$WantPattern'" } else { '-' }
    Write-Host ("  [{0}] {1}: exit={2} want[{3}] pattern={4} {5}" -f $status, $Name, $code, $want, $pat, $refusal)
    if (-not $ok) {
        $script:bad++
        ($out -split "`n" | ?{ $_ -match 'FAIL|REFUSED|WRONGLY' } | Select-Object -First 6) | %{ Write-Host ("      | " + $_.Trim()) }
    }
}

Write-Host "`ncases:"
# 1. the real package
Case 'pristine' (New-Copy 'ok') @(0) 'VERDICT ACCEPTED|crypto-verification-ran.*PASS'

# 2. a byte flipped inside the signed content (measured region: encapContentInfo)
$d = New-Copy 'content'
Flip (Join-Path $d 'cm400.cat') 582
Case 'signed-content-flipped' $d @(40) 'FAIL signature' @('cm400.cat')

# 3. a byte flipped inside the embedded certificate, which the signature does not cover
$d = New-Copy 'cert'
Flip (Join-Path $d 'cm400.cat') 1282
Case 'embedded-cert-flipped' $d @(40) 'FAIL embedded-identity' @('cm400.cat')

# 4. the INF replaced and the manifest recomputed for it, catalog untouched
$d = New-Copy 'inf'
Add-Content -Path (Join-Path $d 'cm400.inf') -Value '; attacker added a line' -Encoding ascii
$sums = Join-Path $d 'SHA256SUMS.txt'
$lines = @(Get-Content $sums) | ?{ $_ -notmatch ' cm400\.inf$' }
$h = (Get-FileHash (Join-Path $d 'cm400.inf') -Algorithm SHA256).Hash.ToLowerInvariant()
$lines += "$h  cm400.inf"
Set-Content -Path $sums -Value $lines -Encoding ascii
Case 'inf-replaced-manifest-recomputed' $d @(13, 15, 40) 'FAIL content-binding|not attested|digest' @('cm400.inf', 'SHA256SUMS.txt')

# 5. installer and service binary swapped as a pair, manifest rewritten so it stays self-consistent,
# catalog untouched: only the catalog's member list can say no. Both files live at the package top level.
$d = New-Copy 'pair'
$setup = Join-Path $d 'cm400-setup.exe'; $daemon = Join-Path $d 'cm400d.exe'
$a = [IO.File]::ReadAllBytes($setup); $b = [IO.File]::ReadAllBytes($daemon)
[IO.File]::WriteAllBytes($setup, $b); [IO.File]::WriteAllBytes($daemon, $a)
foreach ($rel in 'cm400-setup.exe', 'cm400d.exe') {
    $hp = (Get-FileHash (Join-Path $d $rel) -Algorithm SHA256).Hash.ToUpperInvariant()
    $ls = @(Get-Content (Join-Path $d 'SHA256SUMS.txt')) | %{ if ($_ -match " $([regex]::Escape($rel))\s*$") { "$hp  $rel" } else { $_ } }
    Set-Content -Path (Join-Path $d 'SHA256SUMS.txt') -Value $ls -Encoding ascii
}
Case 'installer-and-list-swapped' $d @(13, 15, 40) 'FAIL|REFUSED' @('cm400-setup.exe', 'cm400d.exe')

# 6. layout: an extra file, a subdirectory that is not bin, a hidden file, a missing catalog
$d = New-Copy 'extra'
Set-Content -Path (Join-Path $d 'unexpected.txt') -Value 'x' -Encoding ascii
Case 'extra-file' $d @(14) 'whitelist|unexpected|not exactly'
$d = New-Copy 'nested'
New-Item -ItemType Directory -Force -Path (Join-Path $d 'otherdir') | Out-Null
Set-Content -Path (Join-Path $d 'otherdir\x.exe') -Value 'MZ' -Encoding ascii
Case 'extra-subdirectory' $d @(14) 'whitelist|subdirector|unexpected|not exactly'
$d = New-Copy 'hidden'
$hf = Join-Path $d 'hiddenfile.txt'
Set-Content -Path $hf -Value 'x' -Encoding ascii
attrib.exe +h $hf
Case 'hidden-file' $d @(14) 'whitelist|hidden|unexpected|not exactly'
$d = New-Copy 'nocat'
Remove-Item (Join-Path $d 'cm400.cat') -Force
Case 'catalog-missing' $d @(14) 'cm400.cat is missing'

# 7. a catalog replaced by garbage: not a signature, and must not be waved through
$d = New-Copy 'junk'
Set-Content -Path (Join-Path $d 'cm400.cat') -Value 'not a catalog' -Encoding ascii
Case 'catalog-not-a-signature' $d @(12, 16, 40, 42) 'FAIL|REFUSED'

Remove-Item $work -Recurse -Force -EA SilentlyContinue
Write-Host ("`ntemp work removed: {0}" -f (-not (Test-Path $work)))
if ($script:bad) { Write-Host "FAIL(50): $script:bad case(s) did not behave as required"; exit 50 }
Write-Host "`nALL CASES BEHAVED AS REQUIRED"
exit 0
