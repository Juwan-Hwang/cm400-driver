<#
    bundle_layout.ps1 - the one place that knows how a single-file installer turns back into a package.

    Every existing gate (catalog signature, catalog membership, per-file digests, manifest attestation)
    was written against a package directory, and those judgements must stay exactly as they are: the
    single-file change is about how the bytes reach the machine, not about what counts as trusted. So a
    candidate is expanded into a directory first, and the same gates run over it.

    The expected member set is stated here once. A bundle carrying anything else - a verifier tool, a
    PDB, a second daemon - is refused here rather than quietly shipped.
#>

$script:BUNDLE_MEMBERS = @(
    'cm400.cat',
    'cm400.cat.thumbprint.txt',
    'cm400.cer',
    'cm400.inf',
    'cm400d.exe',
    'LICENSE',
    'SHA256SUMS.txt'
)

function Get-ReleaseAssetNames {
    <#
    .SYNOPSIS
        The exact set of files a release may publish. One, for rc4 onward.
    .DESCRIPTION
        Stated once because a release record's asset list and the count compared against it have to agree.
        An earlier revision of the candidate workflow carried a one-name list beside a `-ne 9` count, which
        is the kind of split that only shows up when somebody reads the file closely.
    #>
    @('cm400-setup.exe')
}

function Get-ExpectedBundleMembers {
    <#
    .SYNOPSIS
        The exact file names a released bundle must carry, and nothing else.
    #>
    param([switch]$NoCatalog)
    $names = $script:BUNDLE_MEMBERS
    if ($NoCatalog) {
        # two files describe the catalog: the catalog itself and the thumbprint recorded for it. An unsigned
        # build has neither, and writing a thumbprint for a catalog that does not exist would be inventing
        # a fact. The release shape always carries both, and `REQUIRED_STAGED` still demands them.
        $names = @($names | Where-Object { $_ -notin @('cm400.cat', 'cm400.cat.thumbprint.txt') })
    }
    $names
}

function Expand-BundledInstaller {
    <#
    .SYNOPSIS
        Extract a single-file installer's payload into a package directory and prove the member set is
        exactly what a release is supposed to contain.
    .OUTPUTS
        The directory, as a string. Throws on any mismatch.
    #>
    param(
        [Parameter(Mandatory)][string]$Installer,
        [Parameter(Mandatory)][string]$To,
        [Parameter(Mandatory)][string]$BundleTool,
        [string[]]$Expected = $null,
        [switch]$NoCatalog
    )
    foreach ($p in $Installer, $BundleTool) {
        if (-not (Test-Path $p)) { throw "missing input: $p" }
    }
    if (-not $Expected) { $Expected = Get-ExpectedBundleMembers -NoCatalog:$NoCatalog }
    if (Test-Path $To) { Remove-Item $To -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $To | Out-Null
    $out = & $BundleTool extract $Installer --to $To 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "the shipped installer's own payload did not verify (exit $LASTEXITCODE):`n$out"
    }
    $got = @(Get-ChildItem $To -File | ForEach-Object { $_.Name } | Sort-Object)
    $want = @($Expected | Sort-Object)
    $missing = @($want | Where-Object { $_ -notin $got })
    $extra = @($got | Where-Object { $_ -notin $want })
    if ($missing.Count -or $extra.Count) {
        throw ("bundle members are not the release set.`n  missing: {0}`n  unexpected: {1}" -f ($missing -join ', '), ($extra -join ', '))
    }
    # nothing may arrive as anything but a plain file: a directory or reparse entry inside the payload is
    # a structure the installer would then be asked to write through
    $odd = @(Get-ChildItem $To -Force | Where-Object {
            $_.PSIsContainer -or (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
        })
    if ($odd.Count) {
        throw "bundle carried non-file entries: $(($odd | ForEach-Object Name) -join ', ')"
    }
    return $To
}

function Get-ReleaseLayoutExpectations {
    <#
    .SYNOPSIS
        What a package directory must hold, and which of those files the manifest must name - stated once,
        for both layouts a candidate can arrive in.
    .DESCRIPTION
        `loose`  : the rc1-rc3 shape. The installer is itself a shipped file, so the digest list covers it.
        `bundled`: the rc4 shape. The directory comes out of the installer's own bundle and cannot contain
                   the host: a file cannot attest its own bytes, and the host keeps changing until it is
                   signed last. The host is judged as the release asset instead - its external SHA-256, its
                   signature, and the pinned catalog identity - which is a different claim and is
                   deliberately not folded into this table.

        Neither layout loses a check. `Files` is still an exact whitelist that fails on anything missing or
        extra, and `MustCover` is still every file the install consumes. A smaller set here reflects a
        smaller package, not a relaxed gate.
    #>
    param([switch]$Bundled, [switch]$NoCatalog)
    if ($Bundled) {
        $members = Get-ExpectedBundleMembers -NoCatalog:$NoCatalog
        return [pscustomobject]@{
            Name          = 'bundled'
            Files         = $members
            MustCover     = @($members | Where-Object { $_ -notin @('SHA256SUMS.txt', 'cm400.cat') })
            HostInPackage = $false
        }
    }
    [pscustomobject]@{
        Name          = 'loose'
        Files         = @('LICENSE', 'SHA256SUMS.txt', 'cm400.cat', 'cm400.cat.thumbprint.txt', 'cm400.cer',
                          'cm400-setup.exe', 'cm400.inf', 'cm400ctl.exe', 'cm400d.exe')
        MustCover     = @('LICENSE', 'cm400.cat.thumbprint.txt', 'cm400.cer', 'cm400-setup.exe', 'cm400.inf',
                          'cm400ctl.exe', 'cm400d.exe')
        HostInPackage = $true
    }
}

function Find-Cm400AppendEnd {
    <#
    .SYNOPSIS
        The byte just past a host's appended bundle, found by the trailer magic.
    .DESCRIPTION
        "End of file minus a constant" is wrong on a signed artifact: signing appends an attribute
        certificate table after the bundle. A mutation aimed by file length would then hit the signature
        and appear to prove something about the container while testing neither.
    #>
    param([Parameter(Mandatory)][string]$Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $magic = [Text.Encoding]::ASCII.GetBytes('CM400BD1')
    for ($i = $bytes.Length - 8; $i -ge 0; $i--) {
        $hit = $true
        for ($j = 0; $j -lt 8; $j++) { if ($bytes[$i + $j] -ne $magic[$j]) { $hit = $false; break } }
        if ($hit) { return @{ end = $i + 8; bytes = $bytes } }
    }
    throw "no bundle trailer found in $Path"
}

function Get-BundleIndexDigests {
    <#
    .SYNOPSIS
        The digests the bundle's own index claims, keyed by file name. Used to tie the directory a gate
        is judging back to the bytes inside the shipped executable, so a gate cannot be pointed at a
        directory that was assembled by hand.
    #>
    param(
        [Parameter(Mandatory)][string]$Installer,
        [Parameter(Mandatory)][string]$BundleTool
    )
    $out = & $BundleTool list $Installer 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "cannot read the bundle index: $out" }
    $map = @{}
    foreach ($line in ($out -split "`r?`n")) {
        if ($line -match '^\s*(\S+)\s+\d+B\s+([0-9A-Fa-f]{64})\s*$') {
            $map[$Matches[1]] = $Matches[2].ToUpperInvariant()
        }
    }
    if ($map.Count -eq 0) { throw "the bundle index listed no members:`n$out" }
    return $map
}

function Assert-PackageComesFromInstaller {
    <#
    .SYNOPSIS
        Fail unless every file in $PackageDir hashes to what the shipped bundle's index says.
    .DESCRIPTION
        This is the link that keeps "we expanded the artifact" from becoming "we judged some directory".
        It is deliberately not a trust decision - the index is an inventory, and the catalog and manifest
        remain the things that establish identity. It only proves the bytes under judgment are the bytes
        inside the file that will be handed to a user.
    #>
    param(
        [Parameter(Mandatory)][string]$Installer,
        [Parameter(Mandatory)][string]$PackageDir,
        [Parameter(Mandatory)][string]$BundleTool
    )
    $index = Get-BundleIndexDigests -Installer $Installer -BundleTool $BundleTool
    $bad = @()
    foreach ($f in @(Get-ChildItem $PackageDir -File)) {
        $claim = $index[$f.Name]
        if (-not $claim) { $bad += "$($f.Name): not listed by the bundle index"; continue }
        $actual = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($actual -ne $claim) { $bad += "$($f.Name): index says $claim, disk says $actual" }
    }
    if ($bad.Count) {
        throw ("the package directory does not match the shipped bundle:`n  " + ($bad -join "`n  "))
    }
    return $index.Count
}
