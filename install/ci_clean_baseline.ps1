#Requires -Version 7
<#
  Assert that this machine is a clean environment for CM400 acceptance, or refuse to continue.

  Read-only. The point of this gate is that a "clean Windows" claim is only meaningful if the machine
  actually looks clean: the pinned release identity must not already be trusted, no CM400Driver service
  may exist, no CM400 driver package may be in the Driver Store, and neither the deployed image nor an
  old ownership record may be on disk. If any of those fail, the run is stopped here rather than
  continuing and reporting a dirty machine's results as a first-install proof.

  Exit codes: 0 clean; 9 not clean (reasons printed); 7 elevation missing where it is needed.
#>
param([string]$SnapshotDir = $env:TEMP)

$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'ci_state_snapshot.ps1')

$s = Get-Cm400State
$problems = @()

if ($s.root.pinned) { $problems += 'the pinned release identity is already in LocalMachine\Root' }
if ($s.tp.pinned) { $problems += 'the pinned release identity is already in LocalMachine\TrustedPublisher' }
if ($s.service_state -ne 'absent') { $problems += "a CM400Driver service already exists (state=$($s.service_state), image=$($s.service_image))" }
if ($s.pk_cm400 -gt 0) { $problems += "$($s.pk_cm400) CM400 driver package(s) are already published in the Driver Store" }
foreach ($what in @(
        @{ name = 'deployment directory'; value = $s.deploy_dir },
        @{ name = 'deployed service image'; value = $s.deployed_exe },
        @{ name = 'ownership record'; value = $s.record },
        @{ name = 'persisted lens state'; value = $s.state_kv }
    )) {
    if ($what.value -ne 'absent') { $problems += "$($what.name) is present ($($what.value))" }
}

Write-Host '=== clean-environment baseline ==='
Write-Host "  Root: total=$($s.root.all.Count) pinned=$($s.root.pinned) legacy=$($s.root.legacy)"
Write-Host "  TrustedPublisher: total=$($s.tp.all.Count) pinned=$($s.tp.pinned) legacy=$($s.tp.legacy)"
Write-Host "  service=$($s.service_state) pk_cm400=$($s.pk_cm400) pk_libwdi=$($s.pk_libwdi)"
Write-Host "  deploy_dir=$($s.deploy_dir) deployed_exe=$($s.deployed_exe) record=$($s.record) state_kv=$($s.state_kv)"
Write-Host "  cm400 devices present: $($s.devices.Count)"
$s.devices | ForEach-Object { Write-Host "    $_" }

$out = Join-Path $SnapshotDir 'cm400-ci-baseline.txt'
Set-Content -Path $out -Value @(
    "root_fingerprints=$($s.root.all -join ',')"
    "tp_fingerprints=$($s.tp.all -join ',')"
    "service_state=$($s.service_state)"
    "pk_cm400=$($s.pk_cm400) pk_libwdi=$($s.pk_libwdi)"
    "deploy_dir=$($s.deploy_dir) deployed_exe=$($s.deployed_exe) record=$($s.record) state_kv=$($s.state_kv)"
) -Encoding utf8
Write-Host "  baseline snapshot: $out"

if ($problems.Count) {
    foreach ($p in $problems) { Write-Host "  NOT CLEAN: $p" }
    # A leftover legacy identity is allowed on purpose: it is a pre-existing certificate this product
    # must never claim as its own, so its presence says nothing about CM400 having been installed.
    Write-Host '::error::this is not a clean environment; refusing to run CM400 acceptance here'
    exit 9
}
Write-Host '  clean: nothing CM400-owned is present, and the pinned identity is untrusted'
exit 0
