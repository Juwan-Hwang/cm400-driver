#Requires -Version 7
<#
  Self-test for the pre-execution candidate verifier and its pure decision helpers.

  Two layers, because they fail differently:

  Layer 1 - the decision functions, driven directly. A signature status that is not on the allow-list
  must be refused; a catalog member whose file name matches while its reference tag does not must be
  refused; a package containing a subdirectory must be refused. These are the cases where the previous
  implementation was blind by construction, and they are checked without needing an attacker-shaped
  catalog to exist.

  Layer 2 - the whole verifier against copies of a real signed package, asserting the refusal reason
  rather than merely a non-zero code:
    good             - passes, or everything below is vacuous;
    tampered-inf     - content changed after signing: membership failure plus digest mismatch;
    tampered-exe     - a shipped binary changed while the list still describes the old one;
    tampered-catalog - the signed catalog modified; where the flipped byte lands decides which refusal
                       appears (no attributable signer, or a broken signature), both are refusals;
    swapped-pair     - installer and digest list replaced as a pair, catalog untouched. The rewritten
                       list is internally consistent, so only the catalog's own member list catches it,
                       and it must be caught without executing the replaced installer;
    extra-file       - an unexpected top-level file;
    nested-dir       - a subdirectory (and hidden file) that a top-level `-File` listing cannot see.

  On the pair swap specifically, measured on this package: both catalog members are hash-only with an
  empty file name, so the old `*|name` branch could never have matched and the refusal did come from the
  tag comparison. The old code was therefore right about this input by accident of the catalog's shape;
  the exact tag comparison plus the fabricated-member tests below remove the accident.

  Needs a signed package to attack (dist\staging by default); without one it exits 2 rather than
  reporting success. Exit 0 = every case behaved as specified; 1 = at least one did not.
#>
param(
    [string]$PackageDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'dist\staging'),
    [string]$WorkRoot = (Join-Path $env:TEMP 'cm400-preverify-selftest'),
    # the pinned-certificate verifier the package cases now depend on; discovered from the build output
    # when not given, because a self-test that quietly skipped that leg would be testing nothing
    [string]$Catsig = ''
)

$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'ci_package_checks.ps1')
if (-not $Catsig) { $Catsig = Find-Cm400Verifier -RepoRoot (Split-Path -Parent $PSScriptRoot) }
if (-not $Catsig) {
    Write-Host '::error::cm400-catsig.exe is not built; the package cases cannot exercise the cryptographic leg'
}
$script:Catsig = $Catsig
$verifier = Join-Path $PSScriptRoot 'ci_preverify_candidate.ps1'
$fails = 0
$passCount = 0

function Ok([string]$name) { $script:passCount++; Write-Host "  ok   $name" }
function Bad([string]$name, [string]$detail) {
    $script:fails++
    Write-Host "  FAIL $name : $detail"
}

function Run-Verifier([string]$name, [string]$dir, [int[]]$wantCodes, [string[]]$wantReasons, [bool]$wantPass) {
    $args = @('-NoProfile','-File',$verifier,'-PackageDir',$dir)
    if ($script:Catsig) { $args += @('-Catsig', $script:Catsig) }
    $out = & pwsh @args 2>&1 | Out-String
    $code = $LASTEXITCODE
    if ($wantPass) {
        if ($code -ne 0) {
            Bad $name "expected acceptance, got exit $code"
            ($out -split "`r?`n" | Where-Object { $_ -match 'FAIL' }) | ForEach-Object { Write-Host "        $($_.Trim())" }
            return
        }
        Ok "$name (accepted)"; return
    }
    if ($wantCodes -notcontains $code) {
        Bad $name "expected exit $($wantCodes -join '/'), got $code"
        ($out -split "`r?`n" | Where-Object { $_ -match 'FAIL|::error' }) | ForEach-Object { Write-Host "        $($_.Trim())" }
        return
    }
    $missing = @($wantReasons | Where-Object { $out -notmatch [regex]::Escape($_) })
    if ($missing.Count) {
        Bad $name "exit $code as expected, but the reason is missing ($($missing -join ' / '))"
        ($out -split "`r?`n" | Where-Object { $_ -match 'FAIL|::error' }) | ForEach-Object { Write-Host "        $($_.Trim())" }
        return
    }
    Ok "$name (exit $code, reason asserted)"
}

function New-Copy([string]$label) {
    $dir = Join-Path $WorkRoot $label
    Remove-Item $dir -Recurse -Force -EA SilentlyContinue
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Copy-Item (Join-Path $PackageDir '*') $dir -Force
    return $dir
}

Write-Host '=== layer 1: decision helpers ==='

# every value PowerShell's own enum can hold, so a future or unexpected one cannot slip through
$statuses = @([Enum]::GetNames([System.Management.Automation.SignatureStatus]))
$allowed = @($statuses | Where-Object { Test-SignatureStatusAllowed -Status $_ })
if (($allowed -join ',') -eq 'Valid,NotTrusted') {
    Ok "signature status allow-list covers the enum ([$($statuses -join ', ')])"
} else {
    Bad 'signature status allow-list' "accepted [$($allowed -join ',')], expected Valid,NotTrusted"
}
foreach ($s in ($statuses | Where-Object { $_ -notin @('Valid', 'NotTrusted') })) {
    if (Test-SignatureStatusAllowed -Status $s) { Bad "status $s" 'must be refused but was allowed' }
}
Ok 'every non-allow-listed signature status is refused'

# the regression this replaces: a member that names the right file but carries a different digest
$nameMatchesTagDoesNot = Test-CatalogMember -Member ([pscustomobject]@{ Tag = 'DEADBEEF'; File = 'cm400.inf' }) `
    -ExpectedTag '7A984792F43EB21218ECE6F05C484ACF6CAAD1B8' -ExpectedFile 'cm400.inf'
if ($nameMatchesTagDoesNot.matched) {
    Bad 'name-matching member with wrong tag' 'must be refused, and this is exactly the old hole'
} else {
    Ok "name-matching member with wrong tag is refused ($($nameMatchesTagDoesNot.why))"
}
$hashOnly = Test-CatalogMember -Member ([pscustomobject]@{ Tag = '7a984792f43eb21218ece6f05c484acf6caad1b8'; File = '' }) `
    -ExpectedTag '7A984792F43EB21218ECE6F05C484ACF6CAAD1B8' -ExpectedFile 'cm400.inf'
if ($hashOnly.matched) { Ok 'hash-only member matches on the tag, case-insensitively' } else { Bad 'hash-only member' "refused: $($hashOnly.why)" }
$wrongName = Test-CatalogMember -Member ([pscustomobject]@{ Tag = '7A984792F43EB21218ECE6F05C484ACF6CAAD1B8'; File = 'other.inf' }) `
    -ExpectedTag '7A984792F43EB21218ECE6F05C484ACF6CAAD1B8' -ExpectedFile 'cm400.inf'
if ($wrongName.matched) { Bad 'tag-matching member naming a different file' 'must be refused' } else { Ok 'tag-matching member naming a different file is refused' }
$pathForm = Test-CatalogMember -Member ([pscustomobject]@{ Tag = '7A984792F43EB21218ECE6F05C484ACF6CAAD1B8'; File = 'sub\cm400.inf' }) `
    -ExpectedTag '7A984792F43EB21218ECE6F05C484ACF6CAAD1B8' -ExpectedFile 'cm400.inf'
if ($pathForm.matched) { Ok 'a recorded relative path is normalised and accepted' } else { Bad 'relative-path member' "refused: $($pathForm.why)" }

Write-Host '=== layer 2: the whole verifier against a real signed package ==='
if (-not (Test-Path (Join-Path $PackageDir 'cm400.cat'))) {
    Write-Host "::error::no signed package at $PackageDir; the package-level cases cannot run"
    exit 2
}
Remove-Item $WorkRoot -Recurse -Force -EA SilentlyContinue
New-Item -ItemType Directory -Force -Path $WorkRoot | Out-Null

# the verifier must never execute package code; a static guard keeps a future edit from adding one.
# Only code lines are scanned - the first version of this guard fired on the phrase
# "`cm400-setup.exe verify-package`" inside the file's own explanatory comment, and narrowing the
# scanned region is the honest fix: loosening the patterns would blind the guard to real invocations.
function Get-CodeOnly([string]$path) {
    # block-aware: the header comment of these scripts is prose and contains the very phrases the guard
    # looks for, so a line filter that only strips `#` would report false positives
    $out = @()
    $inBlock = $false
    foreach ($line in @(Get-Content $path)) {
        $t = $line.Trim()
        if ($t.StartsWith('<#')) { $inBlock = $true }
        if ($inBlock) { if ($t.StartsWith('#>')) { $inBlock = $false }; continue }
        if ($t.StartsWith('#')) { continue }
        $out += $line
    }
    return ($out -join "`n")
}

$guardPatterns = @('&\s*"?\$?\w*setup', 'Start-Process', 'Invoke-Expression', 'cm400-setup\.exe\s+\w', 'iex\s')
$exposable = Get-CodeOnly $verifier
Write-Host ("        (scanned {0} code lines)" -f @($exposable -split "`n").Count)
$hits = @($guardPatterns | Where-Object { $exposable -match $_ })
if ($hits.Count) { Bad 'no-execution guard' "the verifier may run package code: $($hits -join ', ')" } else { Ok 'the verifier contains no execution path for package binaries' }

# positive control for the guard itself: a sibling script that really does run the shipped verifier must
# be flagged by the same patterns. Without this, a guard that matches nothing at all would look like a pass.
$control = Get-CodeOnly (Join-Path $PSScriptRoot 'ci_candidate_verify.ps1')
$controlHits = @($guardPatterns | Where-Object { $control -match $_ })
if ($controlHits.Count) { Ok "the guard is not vacuous (it flags ci_candidate_verify.ps1 on $($controlHits -join ', '))" }
else { Bad 'guard positive control' 'ci_candidate_verify.ps1 executes the package binary, yet the patterns matched nothing' }

Run-Verifier 'good' (New-Copy 'good') 0 @() $true

$d = New-Copy 'tampered-inf'
$b = [IO.File]::ReadAllBytes((Join-Path $d 'cm400.inf')); $b[30] = $b[30] -bxor 0x20
[IO.File]::WriteAllBytes((Join-Path $d 'cm400.inf'), $b)
# The catalog-attestation legs now overlap: the verifier binary also binds the INF and the digest list to
# the catalog's members, so a tampered INF is refused by the cryptographic carrier (40) before the older
# membership refusal (13) is reached. Either refusal is acceptable here as long as the reason names the
# attestation problem - the requirement is that it is refused for the right fact, not for a specific line
# of code that happened to run first.
Run-Verifier 'tampered-inf' $d @(13, 40) @('cm400.inf is not attested by any catalog member', 'digest mismatch') $false

$d = New-Copy 'tampered-exe'
$b = [IO.File]::ReadAllBytes((Join-Path $d 'cm400-setup.exe')); $b[500] = $b[500] -bxor 0xFF
[IO.File]::WriteAllBytes((Join-Path $d 'cm400-setup.exe'), $b)
Run-Verifier 'tampered-exe' $d 15 @('cm400-setup.exe digest mismatch') $false

$d = New-Copy 'tampered-catalog'
$b = [IO.File]::ReadAllBytes((Join-Path $d 'cm400.cat')); $b[1900] = $b[1900] -bxor 0x01
[IO.File]::WriteAllBytes((Join-Path $d 'cm400.cat'), $b)
# offset 1900 lies inside `signerInfos` (measured range [1691,2331)), which the signature does cover, so
# the refusal now comes from the cryptographic leg rather than from PowerShell's status enum. The exit
# code changed from 12 to 40 because the enum stopped being the decision - the package is still refused,
# and now by a check that verifies the arithmetic instead of reporting a trust state.
Run-Verifier 'tampered-catalog' $d @(40) @('FAIL signature', 'crypto-verification-ran') $false

# installer and list replaced together, catalog untouched, the list internally consistent about the
# tampered binary: the catalog's member list is the only thing left that can say no
$d = New-Copy 'swapped-pair'
$b = [IO.File]::ReadAllBytes((Join-Path $d 'cm400-setup.exe')); $b[500] = $b[500] -bxor 0xFF
[IO.File]::WriteAllBytes((Join-Path $d 'cm400-setup.exe'), $b)
$lines = @(Get-Content (Join-Path $d 'SHA256SUMS.txt'))
$h = (Get-FileHash (Join-Path $d 'cm400-setup.exe') -Algorithm SHA256).Hash.ToUpperInvariant()
$lines = @($lines | ForEach-Object { if ($_ -match 'cm400-setup\.exe$') { "$h  cm400-setup.exe" } else { $_ } })
Set-Content -Path (Join-Path $d 'SHA256SUMS.txt') -Value $lines -Encoding ascii
Run-Verifier 'swapped-pair' $d @(13, 40) @('SHA256SUMS.txt is not attested by any catalog member') $false

$d = New-Copy 'extra-file'
Set-Content -Path (Join-Path $d 'not-a-release-file.txt') -Value 'unexpected' -Encoding ascii
Run-Verifier 'extra-file' $d 14 @('not exactly the nine whitelisted files') $false

# what the old top-level-only listing could not see: a directory holding arbitrary content
$d = New-Copy 'nested-dir'
New-Item -ItemType Directory -Force -Path (Join-Path $d 'vendor-tools') | Out-Null
Set-Content -Path (Join-Path $d 'vendor-tools\helper.exe') -Value 'not part of any release' -Encoding ascii
$blind = @(Get-ChildItem $d -File | ForEach-Object { $_.Name }).Count
Write-Host "        (a top-level -File listing sees $blind files and no directory: this is the gap)"
Run-Verifier 'nested-dir' $d 14 @('not exactly the nine whitelisted files') $false

$d = New-Copy 'hidden-file'
Set-Content -Path (Join-Path $d 'invoice.txt') -Value 'hidden' -Encoding ascii
(Get-Item (Join-Path $d 'invoice.txt')).Attributes = 'Hidden'
Run-Verifier 'hidden-file' $d 14 @('not exactly the nine whitelisted files') $false

Write-Host ''
Write-Host "  passed: $passCount  failed: $fails"
if ($fails) { Write-Host "::error::$fails case(s) misbehaved"; exit 1 }
Write-Host '  every case behaved as specified'
exit 0
