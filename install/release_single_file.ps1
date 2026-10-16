<#
    release_single_file.ps1 - assemble and police the one distributable file.

    rc1-rc3 shipped nine named files and the whitelist was a folder listing. With a self-contained
    installer the folder is trivial and the interesting container is inside the executable, so the same
    refusals are applied to both: nothing that is not the release asset may sit beside it, and nothing that
    is not a release member may ride inside it.

    This does not sign or timestamp; it takes whatever `install/single_file_package.ps1` produced - which
    is the only thing that may be published, because its hash is the hash of the final bytes.
#>
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [Parameter(Mandatory)][string]$Installer,
    [Parameter(Mandatory)][string]$BundleTool,
    [string]$Out = '',
    [switch]$NoSigning
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'bundle_layout.ps1')
if (-not $Out) { $Out = Join-Path $RepoRoot 'dist\release' }
if (-not (Test-Path $Installer)) { throw "no installer at $Installer" }

Write-Host '=== release asset: exactly one file ==='
New-Item -ItemType Directory -Force -Path $Out | Out-Null
# clear anything from an earlier run so "exactly one file" can be taken literally
foreach ($stale in @(Get-ChildItem $Out -File -EA SilentlyContinue)) { Remove-Item $stale.FullName -Force }
Copy-Item $Installer (Join-Path $Out 'cm400-setup.exe') -Force
$shipped = Join-Path $Out 'cm400-setup.exe'

$allowed = @('cm400-setup.exe')
$extra = @(Get-ChildItem $Out -File | Where-Object { $_.Name -notin $allowed } | ForEach-Object { $_.Name })
if ($extra.Count) { throw "unexpected release assets beside the installer: $($extra -join ', ')" }
Write-Host '  folder: cm400-setup.exe only'

# the same refusal, applied to what the bundle carries
$expected = Get-ExpectedBundleMembers -NoCatalog:$NoSigning
$null = Expand-BundledInstaller -Installer $shipped -To (Join-Path $Out '.check') -BundleTool $BundleTool -Expected $expected
$forbidden = @('cm400-iks-probe*', 'cm400-etwprobe*', 'cm400-capture-probe*', 'cm400-trust-test*',
    'cm400-catsig*', 'cm400-bundle*', '*.pdb', '*.lib', '*.pfx', '*.password', 'cm400ctl.exe',
    'cm400-setup.exe')
$hits = @()
foreach ($f in @(Get-ChildItem (Join-Path $Out '.check') -File)) {
    foreach ($p in $forbidden) { if ($f.Name -like $p) { $hits += $f.Name } }
}
if ($hits.Count) { throw "forbidden artifacts inside the shipped bundle: $(($hits | Sort-Object -Unique) -join ', ')" }
Write-Host ("  bundle carries exactly: " + ((Get-ChildItem (Join-Path $Out '.check') -File | Sort-Object Name | ForEach-Object { $_.Name }) -join ', '))
Remove-Item (Join-Path $Out '.check') -Recurse -Force

if ($NoSigning) {
    Write-Host '  NOTE: -NoSigning check only; an unsigned installer is not distributable and must never be uploaded'
} else {
    $sig = Get-AuthenticodeSignature $shipped
    Write-Host ("  outer signature: " + $sig.Status + "  signer=" + $(if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { 'none' }))
}

$sha = (Get-FileHash $shipped -Algorithm SHA256).Hash.ToUpperInvariant()
Write-Host ("  size   : " + (Get-Item $shipped).Length + ' bytes')
Write-Host ("  sha256 : $sha")
# the hash is published in the release notes, not as a second download: writing a manifest next to the
# asset would contradict the check two lines above, and a user should have one number to compare
Set-Content -Path (Join-Path (Split-Path -Parent $Out) 'release-hash.txt') -Value ("{0}  cm400-setup.exe`r`nsize: {1} bytes`r`n" -f $sha, (Get-Item $shipped).Length) -Encoding ascii
Write-Host ("  release folder: " + $Out)
# explicit, for the same reason as the gate script: `pwsh -File` would otherwise report the exit code of
# the last native command it ran, and a successful run should never inherit some tool's own status
exit 0
