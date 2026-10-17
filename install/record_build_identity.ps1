#Requires -Version 7
<#
    Writes the build record for a release candidate: which commit produced the bytes, what the binary says
    about itself, and the SHA-256 of every file that would be published. Run it before signing (it records
    the unsigned bytes too, so a later signature can be checked against a stated input rather than assumed).

    What this record does and does not claim:
      - it binds a build to a commit and to the hashes of the produced files;
      - it does not prove who signed anything. That is the job of the Authenticode signature, the catalog
        verification and the pinned-identity check, which run separately and are recorded alongside.
      - a `dirty` tree state is not disqualified silently: it is written down, and the release guard refuses
        to treat a dirty build as a candidate unless the record is regenerated from a clean checkout.
#>
[CmdletBinding()]
param(
    [string]$OutDir = '',
    [switch]$AllowDirty
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $OutDir) { $OutDir = Join-Path $repo 'dist' }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$env:CARGO_TARGET_DIR = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $repo 'target' }

Set-Location $repo
$commit = (& git rev-parse --verify HEAD 2>&1).ToString().Trim()
if ($LASTEXITCODE -ne 0) { throw 'no commit to describe this build by' }
$describe = (& git describe --tags --always --dirty 2>&1).ToString().Trim()
$status = (& git status --porcelain --untracked-files=no 2>&1) -join "`n"
$dirty = ($status.Trim().Length -gt 0)
if ($dirty -and -not $AllowDirty) { throw "the working tree is dirty ($describe); commit the inputs or pass -AllowDirty to record it honestly as a non-candidate" }

# the build itself is the release packaging path, so the recorded bytes are the published bytes
$package = Join-Path $PSScriptRoot 'release_package.ps1'
if (-not (Test-Path $package)) { throw "release_package.ps1 is missing; this script records releases, it does not invent one" }
Write-Host '  building and packaging through release_package.ps1 (unsigned pass)'
& $package | Out-Null
if ($LASTEXITCODE -ne 0) { throw "release_package.ps1 failed with exit $LASTEXITCODE" }

$release = Join-Path $OutDir 'release'
$targets = @('cm400-setup.exe', 'cm400d.exe', 'cm400ctl.exe', 'cm400.cat', 'cm400.inf', 'SHA256SUMS.txt', 'cm400.cer')
$files = @()
foreach ($name in $targets) {
    $p = Join-Path $release $name
    if (Test-Path $p) {
        $i = Get-Item $p
        $files += [ordered]@{ name = $name; bytes = $i.Length; sha256 = (Get-FileHash $p -Algorithm SHA256).Hash; modifiedUtc = $i.LastWriteTimeUtc.ToString('o') }
    }
}
if (-not ($files | Where-Object { $_.name -eq 'cm400-setup.exe' })) { throw 'cm400-setup.exe was not produced; nothing to record' }

$setup = Join-Path $release 'cm400-setup.exe'
$selfReport = @(& $setup --version 2>&1 | ForEach-Object { "$_" })
$sig = Get-AuthenticodeSignature $setup

$record = [ordered]@{
    schema = 'cm400-build-record/1'
    recordedUtc = [DateTime]::UtcNow.ToString('o')
    commit = $commit
    describe = $describe
    treeState = $(if ($dirty) { 'dirty' } else { 'clean' })
    buildCommand = 'install/release_package.ps1'
    cargoTargetDir = $env:CARGO_TARGET_DIR
    toolchain = ((& rustc --version 2>&1) -join ' ')
    cargo = ((& cargo --version 2>&1) -join ' ')
    binarySelfReport = $selfReport
    files = $files
    signatureAtRecordTime = [ordered]@{
        status = "$($sig.Status)"
        signerThumbprint = $(if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { 'none' })
        timestampPresent = [bool]($sig.SignerCertificate -and $sig.SignerCertificate.TimestampSignerCertificate)
    }
    notClaimedByThisRecord = @(
        'who signed these bytes (see the Authenticode signature and cm400-catsig verify)',
        'that the build is reproducible from another machine',
        'that installation works on a machine that has never seen this driver'
    )
}
$path = Join-Path $OutDir 'BUILD-RECORD.json'
$record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path -Encoding utf8
Write-Host ('  record written: ' + $path)
Write-Host ('  commit=' + $commit + '  describe=' + $describe + '  tree=' + $record.treeState)
foreach ($f in $files) { Write-Host ('  {0,-22} {1,9} B  {2}' -f $f.name, $f.bytes, $f.sha256.Substring(0, 16)) }
exit 0
