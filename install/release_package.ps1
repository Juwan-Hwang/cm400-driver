#Requires -Version 7
<#
  Release packaging with an enforced artifact whitelist.

  Why this exists: `cm400-setup install` only requires `cm400d.exe` to sit next to it, so nothing in
  the build process decides which binaries ship. Without that decision written down and enforced, a
  release folder assembled by hand would silently carry experiment tools - `cm400-iks-probe.exe`,
  `cm400-etwprobe.exe`, `cm400-capture-probe.exe` - into a user's machine, and "diagnostic tools are
  not part of the product" would stay a sentence in a document instead of a constraint.

  What this script proves: that a folder contains exactly the whitelisted artifacts, that every one of
  them is hashed for the user to verify, and that the INF/CAT pair is self-consistent.

  What this script does NOT prove: that a clean Windows machine can install the result. Driver
  signature trust is a separate, unresolved release item; see docs/RELEASE-READINESS.md.

  Hash coverage note (deliberate): `SHA256SUMS.txt` covers every file placed in the package, not just
  the installer executable. Verifying only the EXE would leave INF, CAT and the certificate beside it
  free to be swapped, which is not a meaningful integrity check for an installer.
#>
param(
    [string]$Out = '',
    [switch]$SkipBuild,
    # Which catalog to ship. Signing may happen in more than one place (the per-machine flow writes
    # install/cm400.cat, the fixed-identity flow writes dist/fixed-id/cm400.cat), and shipping a
    # catalog that does not match the identity in the package is worse than shipping no catalog: the
    # uninstall-time cleanup would then hunt for the wrong certificate. A consistency gate below
    # refuses that combination.
    [string]$CatPath = '',
    # CI has no publishing certificate and must not have one: the signing environment is separate and
    # private. This mode drops the two signed inputs from the manifest so CI can still verify that the
    # whitelist, the forbidden-artifact rejection and the build all work. A real release run must not
    # use it - without `cm400.cat` there is no package that Windows would accept.
    [switch]$NoSigning,
    # A controlled build machine does not have to trust the release identity locally: the installer
    # establishes that on the target machine at deploy time. This switch accepts exactly one state -
    # verify-package exit 39, which the CLI produces only when the signature was verified
    # cryptographically, the signer equals the pinned identity, membership passed, and the sole
    # failure is that this machine's trust stores lack the certificate. Any other non-zero code is
    # still a hard refusal, and the identity line is checked separately below. Without this switch,
    # even exit 39 fails the run: the operator has to say out loud that this is a build machine.
    [switch]$AllowUntrustedBuild
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
if (-not $Out) { $Out = Join-Path $repo 'dist' }

# Which catalog ships, resolved once and up front. The default used to be `install/cm400.cat`, which is
# the per-machine flow's output: that catalog is signed by a certificate the shipped `.cer` does not
# describe and the pinned identity does not match, so a package built by default would fail the identity
# gate on every machine. The fixed-identity folder is the only sane default, and a missing catalog is an
# error rather than a silent fallback - shipping without one is what `-NoSigning` says out loud.
if (-not $CatPath) { $CatPath = Join-Path $repo 'dist/fixed-id/cm400.cat' }
if (-not $NoSigning -and -not (Test-Path $CatPath)) {
    throw "no catalog at $CatPath; run install/sign_fixed_identity.ps1 (it writes SHA256SUMS.txt inside the catalog) or pass -CatPath"
}
if ($NoSigning) {
    Write-Host 'NOTE: -NoSigning builds an unsigned tree for CI checks. It is not a release: nothing here can be installed.'
}

# The build output directory is not necessarily under the repository (this machine points
# CARGO_TARGET_DIR elsewhere), so ask cargo instead of guessing - a packaging script that looks in
# the wrong folder would silently ship yesterday's binaries or none at all.
$targetDir = (& cargo metadata --format-version 1 --no-deps --manifest-path (Join-Path $repo 'Cargo.toml') | ConvertFrom-Json).target_directory
if (-not $targetDir) { throw 'could not resolve the cargo target directory' }
$bin = Join-Path $targetDir 'release'
Write-Host "target directory: $targetDir"

# Measured on this machine: `CARGO_TARGET_DIR` has pointed at three different trees, so `cargo metadata`
# can name one holding yesterday's binaries. Skipping the build while shipping whatever that directory
# happens to contain would package an installer whose checks are not the checks in the source tree.
# Two things are needed and they are not the same thing: the binaries must EXIST in the named tree, and
# that tree must be current with respect to the source. Comparing file timestamps conflates them and
# reports false positives - editing one bin's source cannot relink another bin, and cargo is right not to.
. (Join-Path $PSScriptRoot 'build_inputs.ps1')
if ($SkipBuild) {
    foreach ($name in 'cm400-setup.exe', 'cm400d.exe', 'cm400ctl.exe') {
        if (-not (Test-Path (Join-Path $bin $name))) {
            throw "$name is not built in $bin; run the build (drop -SkipBuild) or point CARGO_TARGET_DIR at the tree that was built"
        }
    }
    Write-Host ('  ' + (Assert-NothingLeftToCompile -RepoRoot $repo))
}

# --- the whitelist: name -> required? -----------------------------------------------------------
# Anything shipped that is not listed here fails the run, so adding a binary is a decision someone
# has to write down, not a side effect of a build having produced it.
$required = [ordered]@{
    'cm400d.exe'          = 'the service; the only shipped entry point with motor control'
    'cm400-setup.exe'     = 'install / uninstall / certificate cleanup / ACL repair'
    'cm400ctl.exe'        = 'supported diagnostics: status, raise, retract, activity-watch, usbprobe'
    'cm400.inf'           = 'driver package, matches USB\VID_0603&PID_8612&MI_02 only'
    'cm400.cat'           = 'signed catalog for the package above'
    'cm400.cer'           = 'the public half of the publishing certificate, for trust enrollment and fingerprint pinning'
    'cm400.cat.thumbprint.txt' = 'release fingerprint that uninstall uses to locate exactly one certificate'
    'LICENSE'             = 'Apache-2.0'
    'SHA256SUMS.txt'      = 'carried from the signed release folder, so the catalog covers its bytes'
}
$forbiddenPatterns = @('cm400-iks-probe*', 'cm400-etwprobe*', 'cm400-capture-probe*', 'cm400-trust-test*', 'cm400-catsig*', 'cm400-bundle*', '*.pdb', '*.lib', 'recover_libwdi*', 'd4_*', 'w0_*', '*.pfx', '*.password')
if ($NoSigning) {
    foreach ($k in 'cm400.cat', 'cm400.cer') { $required.Remove($k) }
    Write-Host 'NOTE: -NoSigning (CI mode). The output is not a distributable package: no catalog, no certificate.'
}

if (-not $SkipBuild) {
    Write-Host "==> cargo build --release --workspace (bins only, no tests shipped)"
    # The library targets build as dependencies; `--bins` keeps the intent explicit.
    & cargo build --manifest-path (Join-Path $repo 'Cargo.toml') --workspace --bins --release
    if ($LASTEXITCODE -ne 0) { throw "release build failed ($LASTEXITCODE)" }
}

$staging = Join-Path $Out ('staging')
if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
New-Item -ItemType Directory -Path $staging -Force | Out-Null

Write-Host "==> collecting whitelisted artifacts from $bin"
$placed = @()
foreach ($name in $required.Keys) {
    switch ($name) {
        'cm400.inf'               { $src = Join-Path $repo 'install\cm400.inf' }
        'cm400.cat'               { $src = $CatPath }
        'cm400.cer'               { $src = Join-Path $repo 'install\cm400-release.cer' }
        'cm400.cat.thumbprint.txt' { $src = Join-Path $repo 'install\cm400-release.thumbprint.txt' }
        'LICENSE'                 { $src = Join-Path $repo 'LICENSE' }
        default                   { $src = Join-Path $bin $name }
    }
    if (-not (Test-Path $src)) {
        # Missing is reported, not skipped: a package without the catalog or the fingerprint file is
        # not a smaller release, it is a release that cannot install or cannot clean up after itself.
        Write-Host ("  MISSING  {0}  ({1})" -f $name, $required[$name])
        continue
    }
    Copy-Item $src (Join-Path $staging $name) -Force
    $placed += $name
    Write-Host ("  placed   {0}" -f $name)
}

Write-Host "==> refusing forbidden artifacts in the staging folder"
$bad = @()
foreach ($pattern in $forbiddenPatterns) {
    foreach ($hit in @(Get-ChildItem $staging -Filter $pattern -File -EA SilentlyContinue)) {
        $bad += $hit.Name
    }
}
if ($bad.Count) { throw "non-release artifacts reached staging: $($bad -join ', ')" }
Write-Host "  none"

Write-Host "==> SHA256SUMS.txt: carried from the signed release folder, not rewritten"
# Recomputing the digests here would break the property that matters: `SHA256SUMS.txt` is a member of
# the signed catalog, so rewriting it would leave a manifest whose bytes are no longer the ones the
# signature attests, and `cm400-setup install` would (correctly) refuse the package. What this script
# may do is check that what it ships matches the manifest it inherited.
$srcSums = Join-Path (Split-Path -Parent $CatPath) 'SHA256SUMS.txt'
if ($NoSigning) {
    # an unsigned tree has no catalog to inherit from, so the manifest is generated here and labelled
    # as unattested: it can catch a corrupted build, it cannot vouch for one
    Write-Host '  unsigned mode: generating SHA256SUMS.txt locally (NOT attested by any signature)'
    $lines = foreach ($f in (Get-ChildItem $staging -File | Where-Object { $_.Name -ne 'SHA256SUMS.txt' } | Sort-Object Name)) {
        "{0}  {1}" -f (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToUpperInvariant(), $f.Name
    }
    Set-Content -Path (Join-Path $staging 'SHA256SUMS.txt') -Value $lines -Encoding ascii
    $placed += 'SHA256SUMS.txt'
    $srcSums = Join-Path $staging 'SHA256SUMS.txt'
} elseif (-not (Test-Path $srcSums)) {
    throw "no SHA256SUMS.txt beside $CatPath; sign with install/sign_fixed_identity.ps1, which writes the manifest before building the catalog"
} else {
    Copy-Item $srcSums (Join-Path $staging 'SHA256SUMS.txt') -Force
    $placed += 'SHA256SUMS.txt'
}
$bad = 0
$covered = @()
foreach ($row in (Get-Content $srcSums)) {
    $parts = $row -split '\s+', 2
    if ($parts.Count -ne 2) { continue }
    $name = $parts[1].Trim()
    $covered += $name.ToLowerInvariant()
    $file = Join-Path $staging $name
    if (-not (Test-Path $file)) { Write-Host "  absent    $name"; $bad++; continue }
    $actual = (Get-FileHash $file -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($actual -ne $parts[0].Trim().ToUpperInvariant()) { Write-Host "  MISMATCH  $name"; $bad++ }
}
foreach ($need in (@('cm400-setup.exe', 'cm400d.exe', 'cm400.inf') + @(if (-not $NoSigning) { 'cm400.cer' }))) {
    if ($need -notin $covered) { Write-Host "  UNATTESTED $need is used by the install but is not in the manifest"; $bad++ }
}
if ($bad) { throw "$bad manifest problem(s): the staged files are not the files the signed catalog attests" }
Write-Host "  every staged file matches the manifest, and the manifest covers what the installer consumes"

Write-Host "==> integrity of the driver package itself"
if ($NoSigning) {
    # There is no catalog in this folder by design, so a verification attempt here would report a
    # failure that says nothing about the release. Skip it and say why.
    Write-Host '  skipped: -NoSigning means no catalog was placed; nothing to verify'
} else {
    # One identity, three places that must agree: who actually signed the catalog, the public
    # certificate shipped in the package, and the fingerprint uninstall uses to find the certificate
    # to clean up. A package where these differ cannot install and cannot be cleaned up correctly.
    $placedCat = Join-Path $staging 'cm400.cat'
    $placedCer = Join-Path $staging 'cm400.cer'
    $signer = (Get-AuthenticodeSignature $placedCat).SignerCertificate
    $signerTp = if ($signer) { $signer.Thumbprint.ToUpper() } else { '' }
    $cerTp = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $placedCer).Thumbprint.ToUpper()
    $artifactTp = ''
    foreach ($line in (Get-Content (Join-Path $staging 'cm400.cat.thumbprint.txt'))) {
        if ($line -match '^\s*thumbprint\s*=\s*([0-9A-Fa-f]{40})\s*$') { $artifactTp = $Matches[1].ToUpper() }
    }
    Write-Host "  catalog signer     : $(if ($signerTp) { $signerTp } else { '(none - unsigned or unverifiable)' })"
    Write-Host "  shipped certificate: $cerTp"
    Write-Host "  fingerprint artifact: $artifactTp"
    $keyMaterial = @(Get-ChildItem $staging -File | Where-Object { $_.Extension -in '.pfx', '.password' })
    if ($keyMaterial.Count) { throw "release folder must never contain key material: $($keyMaterial.Name -join ', ')" }
    if (-not ($signerTp -and $cerTp -and $artifactTp) -or -not ($signerTp -eq $cerTp -and $cerTp -eq $artifactTp)) {
        throw "the three identity references in the package disagree; shipping this would install one certificate and clean up another"
    }
    Write-Host '  single consistent publishing identity across catalog / certificate / fingerprint record'

    # ...but package files agreeing with each other is only consistency. The last word belongs to the
    # identity compiled into the installer, because all three files above arrive in the same folder
    # and can all be replaced together.
    $probe = Join-Path $staging 'cm400-setup.exe'
    if (-not (Test-Path $probe)) { throw "no installer binary to ask which identity it was built for" }
    $pinned = & $probe pinned-identity 2>&1 | Out-String
    ($pinned -split "`r?`n") | Where-Object { $_.Trim() } | ForEach-Object { Write-Host "  $_".TrimEnd() }
    $pinSha = if ($pinned -match 'sha256_der\s*:\s*([0-9A-Fa-f]{64})') { $Matches[1].ToUpper() } else { '' }
    $pinTp = if ($pinned -match 'sha1_thumbprint\s*:\s*([0-9A-Fa-f]{40})') { $Matches[1].ToUpper() } else { '' }
    $cerSha = (Get-FileHash $placedCer -Algorithm SHA256).Hash.ToUpper()
    Write-Host "  package DER sha256: $cerSha"
    if (-not $pinSha -or -not $pinTp) { throw 'the installer reported no pinned identity; refusing to ship against an unknown anchor' }
    if ($pinSha -ne $cerSha -or $pinTp -ne $cerTp) {
        throw "the package's identity is not the identity the installer was built to accept (pinned $pinSha/$pinTp vs package $cerSha/$cerTp)"
    }
    Write-Host '  package identity matches the anchor compiled into the installer'

    $setup = Join-Path $staging 'cm400-setup.exe'
    if (-not (Test-Path $setup)) { throw "no installer binary to ask about package integrity" }
    # The shipped verifier's exit code is the judgement, because that is what a caller other than a
    # human reads. It used to exit 0 while printing `FAIL`, which let a packaging gate wave through an
    # unverifiable package; the printed lines stay here for the reader, they are no longer the decision.
    $check = & $setup verify-package (Join-Path $staging 'cm400.inf') 2>&1 | Out-String
    $verifyExit = $LASTEXITCODE
    $check -split "`r?`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Host "  $_" }
    Write-Host "  verify-package exit=$verifyExit (0 = everything passes including local trust; 39 = signature verified and identity pinned, but this machine does not trust the certificate)"
    if ($verifyExit -eq 0) {
        Write-Host '  catalog signature, trust, membership and the pinned identity all passed as one verdict'
    } elseif ($verifyExit -eq 39) {
        # the one state that may be reasoned about, and only on explicit instruction
        if ($check -notmatch '4 identity gate\s+: OK') {
            throw "exit 39 without a passing identity gate is a contradiction; refusing to package"
        }
        if ($check -notmatch '6 crypto vs trust\s+:') {
            throw "exit 39 was expected to be explained by judgement 6; refusing to package"
        }
        if ($check -match '2 membership\s+:\s*FAIL') {
            throw "exit 39 with a failed membership is a contradiction; refusing to package"
        }
        if (-not $AllowUntrustedBuild) {
            throw "the package's signature verifies and the signer is the pinned identity, but this machine does not trust it (exit 39). Re-run with -AllowUntrustedBuild if this is a controlled build environment, or enroll the identity first."
        }
        Write-Host '  ACCEPTED FOR A CONTROLLED BUILD: crypto valid + pinned identity + membership OK; only local trust is absent, which `cm400-setup install` establishes on the target machine.'
    } else {
        Write-Host "  note: exit 23 means the signature itself did not verify through WinVerifyTrust and the identity gate did not clear it either; exit 31 means the catalog is not signed by the pinned identity; 30 means the manifest is not attested."
        throw "package integrity not established (verify-package exit $verifyExit)"
    }
    # the identity line has its own code path in the CLI; requiring 0 or the reasoned 39 above still
    # keeps a future change from weakening one gate without the other
    if ($check -notmatch '4 identity gate\s+: OK') {
        throw "the CLI did not report the pinned-identity gate as passed"
    }
}

Write-Host "==> completeness against the whitelist"
$missing = @($required.Keys | Where-Object { $_ -notin $placed })
foreach ($m in $missing) { Write-Host ("  MISSING  {0}  ({1})" -f $m, $required[$m]) }
$unexpected = @(Get-ChildItem $staging -File | Where-Object { $_.Name -notin $required.Keys })
foreach ($u in $unexpected) { Write-Host "  UNEXPECTED $($u.Name)" }
if ($missing.Count -or $unexpected.Count) {
    throw ("package does not match the release manifest ({0} missing, {1} unexpected)" -f $missing.Count, $unexpected.Count)
}

Write-Host "==> OK: $staging"
Write-Host "  Ship this folder as-is. The hashes cover every file the installer will read,"
Write-Host "  not just the executable, so a swapped INF or CAT cannot survive verification."
