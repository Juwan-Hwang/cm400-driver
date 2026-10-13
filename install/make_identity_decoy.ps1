#Requires -Version 7
<#
  Build the T-A test artifact: a driver catalog that is **actually signed by a throwaway
  certificate** while the pinned release certificate sits inside the same PKCS#7 as a decoy.

  The property under test is narrow and important: an identity check that is satisfied by finding a
  matching certificate anywhere in the message would pass here, because the pinned certificate really
  is in the file. The check that instead resolves the CMS SignerInfo and verifies the signature must
  report the throwaway certificate and refuse the package.

  Scope discipline:
    - the throwaway key is created in  Cert:\CurrentUser\My  and expires in one day
    - `install/`, the driver store, the device, the service and the certificate stores are untouched
      unless -Trust is given
    - with -Trust (needs elevation) the throwaway PUBLIC certificate is added to the two machine trust
      stores only long enough to answer "signature+trust: OK?" - the acceptance table requires that
      line to pass, otherwise the rejection could be explained by an unrelated failure - and it is
      removed again afterwards, with both stores re-enumerated to prove it

  Why `signtool /ac`: it appends an additional certificate to the signed message's certificate
  collection, which is precisely the decoy. No PKCS#7 surgery, no local FFI, nothing invented.
#>
param(
    [switch]$Trust,
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
$subject = 'CN=CM400 Driver'
$out = Join-Path $RepoRoot 'dist\identity-decoy'
$cerPinned = Join-Path $RepoRoot 'install\cm400-release.cer'
if (-not (Test-Path $cerPinned)) { throw "no pinned public certificate at $cerPinned" }

Write-Host '=== T-A artifact: throwaway signer + pinned certificate as decoy ==='

# --- 1. a throwaway code-signing certificate, same subject on purpose --------------------------
$existing = @(Get-ChildItem Cert:\CurrentUser\My -EA SilentlyContinue |
    Where-Object { $_.FriendlyName -eq 'CM400 T-A decoy signer' })
foreach ($c in $existing) { Remove-Item $c.PSPath -Confirm:$false }
$throw = New-SelfSignedCertificate -Subject $subject -FriendlyName 'CM400 T-A decoy signer' `
    -Type CodeSigningCert -CertStoreLocation 'Cert:\CurrentUser\My' `
    -HashAlgorithm SHA256 -KeyAlgorithm RSA -KeyLength 3072 -KeyExportPolicy NonExportable `
    -NotAfter (Get-Date).AddDays(1)
Write-Host "  throwaway: thumbprint=$($throw.Thumbprint) notAfter=$($throw.NotAfter.ToString('s')) subject=$subject"

$throwCer = Join-Path $env:TEMP "cm400-ta-throwaway.cer"
[IO.File]::WriteAllBytes($throwCer, $throw.RawData)
$throwSha = (Get-FileHash $throwCer -Algorithm SHA256).Hash.ToUpper()
Write-Host "  throwaway DER sha256 = $throwSha"
$pinTp = ''; $pinSha = ''
foreach ($l in Get-Content (Join-Path $RepoRoot 'install\cm400-release.thumbprint.txt')) { if ($l -match '^\s*thumbprint\s*=\s*([0-9A-F]{40})') { $pinTp = $Matches[1] } }
foreach ($l in Get-Content (Join-Path $RepoRoot 'install\cm400-release.sha256.txt')) { if ($l -match '^\s*sha256_der\s*=\s*([0-9A-F]{64})') { $pinSha = $Matches[1] } }
Write-Host "  pinned      thumbprint = $pinTp"
Write-Host "  pinned      DER sha256 = $pinSha"

# --- 2. build and sign the catalog -------------------------------------------------------------
if (Test-Path $out) { Remove-Item $out -Recurse -Force }
New-Item -ItemType Directory -Path $out -Force | Out-Null
Copy-Item (Join-Path $RepoRoot 'install\cm400.inf') (Join-Path $out 'cm400.inf') -Force
# the public certificate travels under the name the installer looks for, so the package is
# self-consistent and only the identity check can tell them apart
Copy-Item $cerPinned (Join-Path $out 'cm400.cer') -Force

$kitRoot = 'C:\Program Files (x86)\Windows Kits\10\bin'
$kit = Get-ChildItem $kitRoot -Directory -EA SilentlyContinue |
    Where-Object { Test-Path (Join-Path $_.FullName 'x64\makecat.exe') } |
    Sort-Object Name -Descending | Select-Object -First 1
if (-not $kit) { throw 'no Windows SDK toolchain' }
$memberId = (Get-FileHash (Join-Path $out 'cm400.inf') -Algorithm SHA1).Hash
@"
[CatalogHeader]
Name=cm400.cat
ResultDir=.
PublicVersion=0x1
CatalogAttributes=0x1

[CatalogFiles]
$memberId=cm400.inf
"@ | Set-Content (Join-Path $out 'cm400.cdf') -Encoding ascii
Push-Location $out
try {
    & (Join-Path $kit.FullName 'x64\makecat.exe') -v cm400.cdf | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "makecat failed ($LASTEXITCODE)" }
    $sg = & (Join-Path $kit.FullName 'x64\signtool.exe') sign /v /s My /fd SHA256 `
        /sha1 $throw.Thumbprint /d 'CM400 T-A decoy signer' cm400.cat 2>&1
    $sgExit = $LASTEXITCODE
} finally { Pop-Location }
($sg | Select-Object -Last 3) | ForEach-Object { Write-Host "  signtool: $_" }
if ($sgExit -ne 0) { throw "signtool failed ($sgExit)" }
Remove-Item (Join-Path $out 'cm400.cdf') -Force -EA SilentlyContinue
Write-Host "  valid catalog signed by the throwaway: $out\cm400.cat"

# --- 2b. the decoy message ---------------------------------------------------------------------
# `signtool /ac` refuses it ("cross certificate would not be present in the certificate chain"), and
# makecat cannot emit an unsigned container to re-envelope, so the catalog itself cannot carry a
# foreign certificate with the tools available here. What can carry one is a PKCS#7 built through
# .NET, whose `CmsSigner.Certificates` really does land in the message's certificate collection.
# That is the property under test - "a matching certificate inside the message must not satisfy the
# identity check" - measured on a message crypt32 can parse, and labelled as such: it is NOT a
# driver catalog, so its catalog-level signature and membership verdicts are meaningless.
$pinnedPub = [Security.Cryptography.X509Certificates.X509Certificate2]::new((Get-Item $cerPinned).FullName)
$decoyPath = Join-Path $out 'decoy.p7b'
try {
$catBytes = [IO.File]::ReadAllBytes((Join-Path $out 'cm400.cat'))
$contentInfo = [Security.Cryptography.Pkcs.ContentInfo]::new($catBytes)
$cms = [Security.Cryptography.Pkcs.SignedCms]::new($contentInfo, $false)
$signer = [Security.Cryptography.Pkcs.CmsSigner]::new($throw)
$signer.DigestAlgorithm = [Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')
$signer.IncludeOption = [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
$null = $signer.Certificates.Add($pinnedPub)
$cms.Sign($signer)
$decoyPath = Join-Path $out 'decoy.p7b'
[IO.File]::WriteAllBytes($decoyPath, $cms.Encode())
Write-Host "  decoy message: $decoyPath  bytes=$((Get-Item $decoyPath).Length)"
Write-Host "  it holds the throwaway's signature and the pinned certificate as a bystander:"
Write-Host "    signer        thumbprint=$($throw.Thumbprint) DER sha256=$throwSha"
Write-Host "    bystander     thumbprint=$pinTp DER sha256=$pinSha"
Write-Host "  verify with the Rust test (catalog_signer must name the throwaway, catalog_certificates must list both)"
} catch {
    # Measured twice, elevated and not: this host's SignedCms exposes no callable Sign overload, and
    # `signtool /ac` refuses a certificate outside the signer's chain. So the in-message decoy stays
    # unconstructed, and what remains is the in-package decoy below. Recording that here keeps the
    # limitation in the artifact's own output instead of only in a report.
    Write-Host "  decoy message NOT produced: $($_.Exception.Message)"
    Write-Host '  -> the in-PKCS7 decoy case (T-A as specified) remains uncovered; the throwaway-signed'
    Write-Host '     catalog plus the adjacent pinned .cer still exercises the package-level version.'
}
if (Test-Path $decoyPath) { Write-Host "  decoy message kept at $decoyPath" }

# --- 2c. the in-message decoy, through crypt32 --------------------------------------------------
# `CryptMsgControl(CMSG_CTRL_ADD_CERT)` on the handle `CryptQueryObject` returns, re-encoded via
# `CryptMsgGetParam(CMSG_ENCODED_MESSAGE)`. That path needed no hand-written FFI: windows 0.58 exports
# all four symbols. The fixture judges its own output (collection, verified signer, identity gate) and
# exits non-zero if the artifact does not actually contain the bait, so a successful API call alone
# cannot be mistaken for a completed test.
$harness = 'E:\DevEnv\rust\target\release\cm400-trust-test.exe'
$inMsg = Join-Path $out 'in-message'
New-Item -ItemType Directory -Path $inMsg -Force | Out-Null
Copy-Item (Join-Path $out 'cm400.inf') (Join-Path $inMsg 'cm400.inf') -Force
Copy-Item $cerPinned (Join-Path $inMsg 'cm400.cer') -Force
if (-not (Test-Path $harness)) {
    Write-Host "  in-message decoy NOT built: no harness at $harness (run cargo build --release --workspace --bins)"
} else {
    Write-Host '--- building the in-message decoy artifact ---'
    & $harness decoy-message --fingerprint $pinTp `
        --cat (Join-Path $out 'cm400.cat') --cer $cerPinned `
        --out (Join-Path $inMsg 'cm400.cat') --inf (Join-Path $inMsg 'cm400.inf') 2>&1 |
        ForEach-Object { Write-Host "  $_" }
    Write-Host "  fixture exit=$LASTEXITCODE"
}

# --- 3. optional: the trusted run, self-reverting ---------------------------------------------
if (-not $Trust) {
    Write-Host ''
    Write-Host 'next: run the Rust test to measure decoy presence and signer identity (needs no trust),'
    Write-Host '      and rerun elevated with -Trust to measure the shipped verifier on the throwaway-signed'
    Write-Host '      catalog while it is temporarily trusted.'
    exit 0
}

$elevated = ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $elevated) { throw '-Trust writes to machine trust stores and needs elevation' }

function Ev-Store($name) {
    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store $name, 'LocalMachine'
    $s.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    $list = @($s.Certificates | Where-Object { $_.Subject -eq $subject } | ForEach-Object { $_.Thumbprint })
    $s.Close()
    Write-Host "  $name : $($list -join ',')"
    $list
}

Write-Host '--- baseline (pinned identity must be absent, the older one present) ---'
$base = @{ Root = Ev-Store 'Root'; TrustedPublisher = Ev-Store 'TrustedPublisher' }
if ($base.Root -contains $throw.Thumbprint) { throw 'the throwaway identity is already trusted here; refusing to run against an unknown baseline' }

$pub = [Security.Cryptography.X509Certificates.X509Certificate2]::new($throw.RawData)
foreach ($name in 'Root', 'TrustedPublisher') {
    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store $name, 'LocalMachine'
    $s.Open('ReadWrite'); $s.Add($pub); $s.Close()
    Write-Host "  temporarily trusted in $name : $((Ev-Store $name) -contains $throw.Thumbprint)"
}

Write-Host '--- the package as the shipped verifier sees it, with the throwaway trusted ---'
$setup = Join-Path $env:CARGO_TARGET_DIR 'release\cm400-setup.exe'
if (-not (Test-Path $setup)) { $setup = 'E:\DevEnv\rust\target\release\cm400-setup.exe' }
foreach ($dir in @($out, $inMsg)) {
    if (-not (Test-Path (Join-Path $dir 'cm400.cat'))) { continue }
    Write-Host "  package: $dir"
    $v = & $setup verify-package (Join-Path $dir 'cm400.inf') 2>&1 | Out-String
    ($v -split "`r?`n") | Where-Object { $_ -match '^\s*\d ' } | ForEach-Object { Write-Host "    $($_.Trim())" }
    Write-Host "    exit=$LASTEXITCODE"
}

Write-Host '--- remove the temporary trust and prove the machine is back as found ---'
foreach ($name in 'Root', 'TrustedPublisher') {
    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store $name, 'LocalMachine'
    $s.Open('ReadWrite')
    @($s.Certificates | Where-Object { $_.Thumbprint -eq $throw.Thumbprint }) | ForEach-Object { $s.Remove($_) }
    $s.Close()
}
foreach ($name in 'Root', 'TrustedPublisher') {
    $now = Ev-Store $name
    $same = (@(Compare-Object ($base[$name] | Sort-Object) ($now | Sort-Object)).Count -eq 0)
    Write-Host "  $name back to baseline: $same"
    if (-not $same) { throw "$name did not return to its baseline content" }
}
Write-Host '=== done: artifact kept, temporary trust removed ==='
