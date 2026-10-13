#Requires -Version 7
<#
  Read-only snapshot of everything a CM400 install or uninstall is supposed to change.

  Dot-source this from the CI scripts (`Get-Cm400State`) or run it directly with -Out to write a
  snapshot file. It queries and lists; it never stops a service, deletes a file or touches a store.

  Two facts cannot be read without elevation - the ownership record and the deployed image, both
  deliberately closed to an ordinary token - so the snapshot records them as `unreadable` instead of
  `absent`. "Could not look" must never be reported as "not there"; that conflation is exactly the bug
  class this project has already been burned by twice.
#>

param(
    [string]$Out = '',
    # compare the snapshot about to be written against an earlier one; any difference is drift, which is
    # how "this step was read-only" gets proven instead of asserted
    [string]$Baseline = ''
)

function Get-Cm400State {
    $pinnedSha1 = '954E6103349748270B90C8A8A68652A44946ABF1'
    $legacySha1 = '346DF6063A90FA2A877384066E8CA0D391438F07'

    $svc = Get-CimInstance Win32_Service -Filter "Name='CM400Driver'" -EA SilentlyContinue
    $storeOf = {
        param($name)
        $list = @(Get-ChildItem "Cert:\LocalMachine\$name" -EA SilentlyContinue | ForEach-Object { $_.Thumbprint })
        if (-not $list -and -not (Test-Path "Cert:\LocalMachine\$name")) {
            return [pscustomobject]@{ readable = $false; all = @(); pinned = $false; legacy = $false }
        }
        [pscustomobject]@{
            readable = $true
            all      = @($list | Sort-Object)
            pinned   = [bool](@($list | Where-Object { $_ -eq $pinnedSha1 }).Count)
            legacy   = [bool](@($list | Where-Object { $_ -eq $legacySha1 }).Count)
        }
    }

    $pk = & pnputil.exe /enum-drivers 2>&1 | Out-String
    $blocks = @($pk -replace "`r`n", "`n" -split "`n`n")

    # the data paths the lifecycle owns, and the service image it runs
    $record = 'C:\ProgramData\CM400\state\trust-ownership.kv'
    $deployed = 'C:\Program Files\CM400\bin\cm400d.exe'
    $stateKv = 'C:\ProgramData\CM400\state\state.kv'
    $presence = {
        param($path)
        if (-not (Test-Path $path)) { return 'absent' }
        # Test-Path only proves the name resolves; the deployed image and the ownership record deny a
        # read to an ordinary token while still listing, so "present" has to mean "we actually read it"
        try {
            if (Test-Path $path -PathType Container) { $null = Get-ChildItem $path -EA Stop; return 'present' }
            $null = Get-Content $path -TotalCount 1 -EA Stop
            return 'present'
        }
        catch { return 'unreadable' }
    }

    [pscustomobject]@{
        service_state = $(if ($svc) { $svc.State } else { 'absent' })
        service_image = $(if ($svc) { $svc.PathName } else { '' })
        root          = & $storeOf 'Root'
        tp            = & $storeOf 'TrustedPublisher'
        pk_cm400      = @($blocks | Where-Object { $_ -match 'cm400' -and $_ -notmatch 'libwdi' }).Count
        pk_libwdi     = @($blocks | Where-Object { $_ -match 'libwdi' }).Count
        deploy_dir    = & $presence 'C:\Program Files\CM400'
        deployed_exe  = & $presence $deployed
        record        = & $presence $record
        state_kv      = & $presence $stateKv
        devices       = @(Get-PnpDevice -PresentOnly -EA SilentlyContinue |
                Where-Object { $_.InstanceId -like 'USB\VID_0603&PID_8612*' } |
                ForEach-Object { "{0} status={1}" -f $_.InstanceId, $_.Status })
    }
}

if (-not [string]::IsNullOrEmpty($Out)) {
    $s = Get-Cm400State
    $lines = @(
        "service_state=$($s.service_state)"
        "service_image=$($s.service_image)"
        "root_readable=$($s.root.readable) root_pinned=$($s.root.pinned) root_legacy=$($s.root.legacy) root_total=$($s.root.all.Count)"
        "tp_readable=$($s.tp.readable) tp_pinned=$($s.tp.pinned) tp_legacy=$($s.tp.legacy) tp_total=$($s.tp.all.Count)"
        "root_fingerprints=$($s.root.all -join ',')"
        "tp_fingerprints=$($s.tp.all -join ',')"
        "pk_cm400=$($s.pk_cm400) pk_libwdi=$($s.pk_libwdi)"
        "deploy_dir=$($s.deploy_dir) deployed_exe=$($s.deployed_exe) record=$($s.record) state_kv=$($s.state_kv)"
        "devices=$($s.devices -join ' | ')"
    )
    Set-Content -Path $Out -Value $lines -Encoding utf8
    $lines | ForEach-Object { Write-Host "  $_" }

    if ($Baseline) {
        if (-not (Test-Path $Baseline)) {
            Write-Host "::error::no baseline at $Baseline to compare against"
            exit 10
        }
        $was = @(Get-Content $Baseline)
        $now = @($lines)
        $diff = @(Compare-Object $was $now)
        if ($diff.Count) {
            Write-Host "  DRIFT against $Baseline :"
            $diff | ForEach-Object { Write-Host ("    {0} {1}" -f $_.SideIndicator, $_.InputObject) }
            Write-Host '::error::a step that was supposed to be read-only changed the machine state'
            exit 10
        }
        Write-Host "  no drift against $Baseline ($($now.Count) recorded fields identical)"
    }
}
