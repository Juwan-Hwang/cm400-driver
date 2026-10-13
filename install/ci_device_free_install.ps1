#Requires -Version 7
<#
  Device-free acceptance of a signed candidate: the installer must fail at the interface check, roll
  its trust write back, and leave a machine that its own uninstall can bring fully clean.

  This runs on a throwaway VM with no CM400 attached, as elevated. It is deliberately not a proof that
  installation works - there is no hardware here. It proves four specific things:

    1. the candidate is refused at the stage the design says it is refused (device interface), and the
       refusal is read out of the installer's own stage output, not inferred from one exit number;
    2. the trust the installer wrote before reaching that stage is rolled back, confirmed by re-reading
       both certificate stores;
    3. nothing half-installed stays behind that is invisible: a service, a deployed image, a driver
       package and the ownership record are each reported as they actually are;
    4. the residue that is expected by design - a staged driver package - is recoverable by the normal
       uninstall, which is then run and verified rather than assumed.

  Exit codes: 0 all as expected; 21 the run did not fail where it should have; 22 trust was not rolled
  back; 23 leftovers that no uninstall can explain; 24 the recovery uninstall did not finish the job.
#>
param(
    [Parameter(Mandatory = $true)][string]$PackageDir,
    [string]$LogDir = $env:TEMP
)

$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'ci_state_snapshot.ps1')

$setup = Join-Path $PackageDir 'cm400-setup.exe'
$inf = Join-Path $PackageDir 'cm400.inf'
$installLog = Join-Path $LogDir 'cm400-ci-install-attempt.txt'
$uninstallLog = Join-Path $LogDir 'cm400-ci-recovery-uninstall.txt'

$before = Get-Cm400State
Write-Host '=== device-free install acceptance ==='
Write-Host "  before: service=$($before.service_state) pk_cm400=$($before.pk_cm400) root_pinned=$($before.root.pinned) tp_pinned=$($before.tp.pinned) deploy=$($before.deploy_dir) record=$($before.record)"

if ($before.devices.Count -gt 0) {
    Write-Host '::error::this machine has CM400 hardware attached; the device-free job must not run here'
    exit 21
}

Push-Location $PackageDir
try {
    $out = & $setup install $inf 2>&1 | Out-String
    $code = $LASTEXITCODE
}
finally {
    Pop-Location
}
Set-Content -Path $installLog -Value $out -Encoding utf8
($out -split "`r?`n" | Where-Object { $_.Trim() }) | Select-Object -First 40 | ForEach-Object { Write-Host "  in| $($_.TrimEnd())" }
Write-Host "  install exit=$code ; transcript: $installLog"

# The stage has to be named by the installer's own words, not just by a number.
$reachedInterface = $out -match 'interface\s+: (NOT FOUND|FOUND)'
$refusedHere = $out -match 'INSTALL NOT ACCEPTED: our own interface does not exist'
$acceptedInstead = $out -match 'ACCEPTED: interface enumerated through our own GUID'
if ($code -eq 0 -or $acceptedInstead) {
    Write-Host '::error::the installer reported success without a device; the expected refusal never happened'
    exit 21
}
if (-not ($reachedInterface -and $refusedHere) -or $code -ne 24) {
    Write-Host "::error::installer failed earlier than the interface check (exit $code, reachedInterface=$reachedInterface, refusedHere=$refusedHere)"
    exit 21
}
Write-Host '  refused at the device-interface stage, as designed'

$after = Get-Cm400State
Write-Host "  after: service=$($after.service_state) pk_cm400=$($after.pk_cm400) root_pinned=$($after.root.pinned) tp_pinned=$($after.tp.pinned) deploy=$($after.deploy_dir) deployed=$($after.deployed_exe) record=$($after.record)"

# rollback proof: the pinned identity must not survive in either store
$leaked = @()
if ($after.root.pinned) { $leaked += 'LocalMachine\Root still lists the pinned identity' }
if ($after.tp.pinned) { $leaked += 'LocalMachine\TrustedPublisher still lists the pinned identity' }
if ($leaked.Count) {
    foreach ($l in $leaked) { Write-Host "  ROLLBACK INCOMPLETE: $l" }
    Write-Host '::error::trust written before the interface check was not rolled back'
    exit 22
}
Write-Host '  trust rolled back: neither store lists the pinned identity'

# half-install proof: no service, no deployed image. A driver package is expected and handled below.
$unexplained = @()
if ($after.service_state -ne 'absent') { $unexplained += "service exists ($($after.service_state)) although registration happens after the interface check" }
if ($after.deploy_dir -ne 'absent') { $unexplained += "deployment directory exists ($($after.deploy_dir))" }
if ($after.state_kv -ne 'absent') { $unexplained += "persisted lens state exists ($($after.state_kv))" }
if ($unexplained.Count) {
    foreach ($u in $unexplained) { Write-Host "  UNEXPECTED: $u" }
    Write-Host '::error::the refused install left state that the documented flow does not produce'
    exit 23
}
Write-Host '  no service, no deployed image, no state file'
# The record is written during trust establishment. Whether it survives a rollback is a design fact this
# job reports instead of asserting, because a record whose certificates are gone cannot authorize any
# deletion (cleanup re-reads the stores) - the observable requirement is the store state above.
Write-Host "  ownership record after the refused install: $($after.record)"

if ($after.pk_cm400 -eq 0) {
    Write-Host '  no CM400 driver package left behind (the stage step did not commit one)'
    exit 0
}

Write-Host "  $($after.pk_cm400) CM400 driver package(s) staged before the refusal - verifying the documented recovery path"
Push-Location $PackageDir
try {
    $un = & $setup uninstall 2>&1 | Out-String
    $unCode = $LASTEXITCODE
}
finally {
    Pop-Location
}
Set-Content -Path $uninstallLog -Value $un -Encoding utf8
($un -split "`r?`n" | Where-Object { $_.Trim() }) | Select-Object -Last 24 | ForEach-Object { Write-Host "  un| $($_.TrimEnd())" }
Write-Host "  recovery uninstall exit=$unCode ; transcript: $uninstallLog"

$final = Get-Cm400State
Write-Host "  final: service=$($final.service_state) pk_cm400=$($final.pk_cm400) root_pinned=$($final.root.pinned) tp_pinned=$($final.tp.pinned) deploy=$($final.deploy_dir) record=$($final.record)"
$bad = @()
if ($unCode -ne 0) { $bad += "the recovery uninstall returned $unCode (it must finish the job, not refuse it)" }
if ($final.pk_cm400 -ne 0) { $bad += "the staged package is still in the Driver Store ($($final.pk_cm400))" }
if ($final.service_state -ne 'absent') { $bad += 'a service still exists' }
if ($final.root.pinned -or $final.tp.pinned) { $bad += 'the pinned identity is trusted after uninstall' }
if ($final.deploy_dir -ne 'absent') { $bad += "deployment directory still present ($($final.deploy_dir))" }
# the machine must not have lost anything that was not ours: the pre-existing baseline stores must match
if ($final.root.all.Count -ne $before.root.all.Count) { $bad += "Root changed size during the whole run ($($before.root.all.Count) -> $($final.root.all.Count))" }
if ($final.tp.all.Count -ne $before.tp.all.Count) { $bad += "TrustedPublisher changed size during the whole run ($($before.tp.all.Count) -> $($final.tp.all.Count))" }
if ($bad.Count) {
    foreach ($b in $bad) { Write-Host "  RECOVERY INCOMPLETE: $b" }
    Write-Host '::error::the recovery uninstall did not return this machine to the pre-run baseline'
    exit 24
}
Write-Host '  recovery verified: back to the pre-run baseline, nothing of ours left, nothing of anyone else touched'
exit 0
