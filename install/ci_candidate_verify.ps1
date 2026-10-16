#Requires -Version 7
<#
  Verify a downloaded release candidate before anything on this machine is allowed to act on it.

  Order matters and is the whole point. The expectations come from the repository checkout (pinned
  identity, required file list); the observations come from the downloaded folder. A candidate that
  disagrees with the repository fails here, before any installer, certificate store or Driver Store is
  touched.

  Exit codes:
    0  everything checked out
    11 missing/unreadable file, or the digest list does not cover the folder it lives in
    12 identity mismatch against the pinned values in the repository
    13 the shipped verifier refused the package for a reason other than "this machine does not trust
       the pinned identity yet"
#>
param(
    [Parameter(Mandatory = $true)][string]$PackageDir,
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    # the rc4 shape: the package is the payload of $Installer, and $Installer is what gets run. Passing
    # -Bundled without -Installer fails in stage 1 rather than quietly falling back to a package copy of
    # an installer that is not the shipped file.
    [switch]$Bundled,
    [string]$Installer = '',
    [string]$BundleTool = '',
    # where cm400-catsig.exe lives. Without it the pre-execution gate has to guess from the build
    # environment, and a caller whose CARGO_TARGET_DIR differs from this script's view gets exit 42 - a
    # missing verifier reported as a candidate problem. Passing it changes no verdict: an absent or
    # unusable verifier still fails the gate, it just fails for the reason it should name.
    [string]$Catsig = ''
)

$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'bundle_layout.ps1')

# Order is the substance of this step. The catalog signature, membership and digest checks are decided
# without running anything from the package; the package's own verifier is consulted afterwards and is
# expected to agree. Its verdict alone was never evidence about itself: an installer replaced together
# with its digest list is free to report "membership OK" while the catalog it claims to be listed in
# says otherwise.
$pre = Join-Path $PSScriptRoot 'ci_preverify_candidate.ps1'
if (-not (Test-Path $pre)) {
    Write-Host '::error::the pre-execution verifier is missing; refusing to fall back to self-attestation'
    exit 16
}
Write-Host '--- stage 1: pre-execution verification (no candidate code) ---'
if ($Bundled -and (-not $Installer -or -not $BundleTool)) {
    Write-Host '::error::-Bundled needs -Installer and -BundleTool; refusing to verify a payload it cannot tie to a shipped host'
    exit 17
}
& $pre -PackageDir $PackageDir -RepoRoot $RepoRoot -Bundled:$Bundled -Installer $Installer -BundleTool $BundleTool -Catsig $Catsig
$preCode = $LASTEXITCODE
if ($preCode -ne 0) {
    Write-Host "::error::pre-execution verification failed ($preCode); the candidate is not accepted and nothing from it was executed"
    exit $preCode
}

$fail = 0
function Bad([int]$code, [string]$msg) {
    Write-Host "  FAIL: $msg"
    $script:fail = [Math]::Max($script:fail, $code)
}

$PackageDir = (Resolve-Path $PackageDir).Path
Write-Host "=== candidate verification ==="
Write-Host "  package : $PackageDir"

$layout = Get-ReleaseLayoutExpectations -Bundled:$Bundled
$required = $layout.Files
foreach ($r in $required) {
    if (-not (Test-Path (Join-Path $PackageDir $r))) { Bad 11 "required file missing: $r" }
}
if ($layout.HostInPackage -and -not $Bundled) {
    Write-Host '  layout : loose (the installer ships beside its package files)'
} else {
    Write-Host "  layout : bundled - the host is the shipped installer, not a package file: $Installer"
}

# no private material and no experiment tooling may ride along in a public package
$forbidden = @(Get-ChildItem $PackageDir -File -EA SilentlyContinue |
        Where-Object { $_.Name -match '\.pfx$|\.password$|private|trust-test|decoy|etwprobe|iks-probe|capture-probe|_run_|\.pdb$|\.log$' })
if ($forbidden.Count) { Bad 11 "forbidden files in the package: $($forbidden.Name -join ', ')" }

Write-Host '--- digest list coverage (every file, not just the executable) ---'
$manifest = @(Get-Content (Join-Path $PackageDir 'SHA256SUMS.txt') -EA SilentlyContinue)
if (-not $manifest.Count) { Bad 11 'SHA256SUMS.txt is empty or unreadable' }
$listed = @{}
foreach ($line in $manifest) {
    if ($line -match '^([0-9a-fA-F]{64})\s+\*?(.+)$') { $listed[$Matches[2].Trim().ToLowerInvariant()] = $Matches[1].ToUpperInvariant() }
}
foreach ($f in @(Get-ChildItem $PackageDir -File)) {
    $name = $f.Name.ToLowerInvariant()
    # the list cannot attest to itself, and the catalog is the thing that signs it instead
    if ($name -eq 'sha256sums.txt' -or $name -eq 'cm400.cat') { continue }
    if (-not $listed.ContainsKey($name)) { Bad 11 "$($f.Name) is in the package but not in SHA256SUMS.txt"; continue }
    $actual = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($actual -ne $listed[$name]) { Bad 11 "$($f.Name) digest mismatch: manifest $($listed[$name]) actual $actual" }
}
foreach ($name in $listed.Keys) {
    if (-not (Test-Path (Join-Path $PackageDir $name) )) { Bad 11 "SHA256SUMS.txt lists $name which is not in the package" }
}
Write-Host "  listed entries: $($listed.Count)"

Write-Host '--- pinned identity, from the repository rather than from the package ---'
$wantThumb = $null
foreach ($line in @(Get-Content (Join-Path $RepoRoot 'install\cm400-release.thumbprint.txt') -EA SilentlyContinue)) {
    if ($line -match '^\s*thumbprint\s*=\s*([0-9A-Fa-f]{40})\s*$') { $wantThumb = $Matches[1].ToUpperInvariant() }
}
if (-not $wantThumb) { Bad 12 'repository thumbprint artifact is unreadable' }
$gotThumb = $null
foreach ($line in @(Get-Content (Join-Path $PackageDir 'cm400.cat.thumbprint.txt') -EA SilentlyContinue)) {
    if ($line -match '^\s*thumbprint\s*=\s*([0-9A-Fa-f]{40})\s*$') { $gotThumb = $Matches[1].ToUpperInvariant() }
}
if (-not $gotThumb) { Bad 12 'the package thumbprint file names no 40-hex thumbprint' }
if ($wantThumb -and $gotThumb -and $gotThumb -ne $wantThumb) { Bad 12 "package names $gotThumb but the repository pins $wantThumb" }
Write-Host "  pinned SHA-1 : $gotThumb"

try {
    $cer = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new((Join-Path $PackageDir 'cm400.cer'))
}
catch {
    Bad 12 "cm400.cer cannot be parsed: $($_.Exception.Message)"
    exit $fail
}
if ($cer.HasPrivateKey) { Bad 12 'the shipped certificate carries a private key' }
$sha256Der = [BitConverter]::ToString(
    [System.Security.Cryptography.SHA256]::Create().ComputeHash($cer.RawData)).Replace('-', '')
$wantDer = $null
foreach ($line in @(Get-Content (Join-Path $RepoRoot 'install\cm400-release.sha256.txt') -EA SilentlyContinue)) {
    if ($line -match '^\s*sha256_der\s*=\s*([0-9A-Fa-f]{64})\s*$') { $wantDer = $Matches[1].ToUpperInvariant() }
}
if ($wantDer -and $sha256Der -ne $wantDer) { Bad 12 "certificate DER SHA-256 $sha256Der != pinned $wantDer" }
Write-Host "  subject      : $($cer.Subject)"
Write-Host "  self-signed  : $($cer.Subject -eq $cer.Issuer)"
Write-Host "  DER SHA-256  : $sha256Der"
# the usage OIDs live inside the extension's payload; the extension's own OID is 2.5.29.37, so look the
# extension up by type and then read its usages (matching on Oid.Value here would never match)
$ekuOids = @()
foreach ($ext in $cer.Extensions) {
    if ($ext -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
        $ekuOids += @($ext.EnhancedKeyUsages | ForEach-Object { $_.Value })
    }
}
if ($ekuOids -contains '1.3.6.1.5.5.7.3.3') {
    Write-Host "  EKU          : present (1.3.6.1.5.5.7.3.3, Microsoft code signing)"
} else {
    Bad 12 "the certificate does not carry the code-signing EKU the release identity is defined by (found: $($ekuOids -join ', '))"
}
Write-Host "  not after    : $($cer.NotAfter.ToString('s'))"

Write-Host '--- stage 2: the shipped verifier, as corroboration of the independent result ---'
# in the bundled layout the installer IS the shipped host and the directory is its payload, so the run has
# to be told which layout it is judging rather than left to apply the loose rule to a staged package
$setup = if ($Bundled) { $Installer } else { Join-Path $PackageDir 'cm400-setup.exe' }
if (-not (Test-Path $setup)) {
    Bad 11 "no installer to consult at $setup"
    Write-Host "::error::the installer to consult is missing; failing with the accumulated code"
    exit [Math]::Max($fail, 11)
}
$vpArgs = @('verify-package', (Join-Path $PackageDir 'cm400.inf'))
if ($Bundled) { $vpArgs += '--staged' }
$out = & $setup @vpArgs 2>&1 | Out-String
$code = $LASTEXITCODE
($out -split "`r?`n" | Where-Object { $_.Trim() }) | ForEach-Object { Write-Host "  vp| $($_.TrimEnd())" }
Write-Host "  verify-package exit=$code"
# 0 = passes including local trust (should not be the normal case on a clean machine),
# 39 = signature verified and the signer is the pinned identity, only this machine does not trust it.
# Anything else is a rejection, and 23/29/30/31/33/34 are never acceptable here.
if ($code -ne 0 -and $code -ne 39) { Bad 13 "verify-package returned $code; the candidate is not the pinned, intact package" }

if ($fail -eq 0) { Write-Host '  candidate verified'; exit 0 }
Write-Host "::error::candidate verification failed (code $fail)"
exit $fail
