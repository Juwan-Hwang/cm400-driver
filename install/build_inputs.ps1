#Requires -Version 7
<#
  Which files count as build inputs, and how fresh the shipped binaries have to be.

  Why a shared module: both `install/sign_fixed_identity.ps1` and `install/release_package.ps1` need to
  refuse a binary older than the sources it is supposed to contain. The first version of that check only
  walked `crates/`, which missed the workspace manifest and the lock file at the repository root - the
  two inputs that decide which dependency versions get compiled in, and this repository commits
  `Cargo.lock` deliberately. A freshness check that cannot see the lock file cannot claim the shipped
  binary matches the current build inputs.

  `git ls-files` is used when available, because "what the build reads" is best answered by what the
  repository tracks rather than by a guessed extension list. The directory walk is the fallback, and it
  is broader than the earlier version.
#>

Set-StrictMode -Version Latest

# Sources that feed the compiled binaries, plus the manifests that decide what gets linked in.
$BuildInputPatterns = @(
    '*.rs', '*.toml', '*.c', '*.cpp', '*.cc', '*.cxx', '*.h', '*.hpp',
    '*.rc', '*.def', '*.asm', '*.S', '*.proto', '*.wasm'
)

function Test-RequiredBuildInputs {
    <#
      The build cannot be described without these, and a release run that silently proceeded without one
      would be measuring a different tree than the one that produced the binaries.
    #>
    param([Parameter(Mandatory)][string]$RepoRoot)
    $missing = @()
    foreach ($required in @('Cargo.toml', 'Cargo.lock')) {
        if (-not (Test-Path (Join-Path $RepoRoot $required))) { $missing += $required }
    }
    if (-not (Test-Path (Join-Path $RepoRoot 'crates'))) { $missing += 'crates/' }
    if ($missing) {
        throw "required build inputs are missing from $RepoRoot : $($missing -join ', ')"
    }
}

function Get-BuildInputFiles {
    param([Parameter(Mandatory)][string]$RepoRoot)
    Test-RequiredBuildInputs -RepoRoot $RepoRoot

    $tracked = @()
    try {
        $tracked = @(& git -C $RepoRoot ls-files 2>$null)
    }
    catch {
        $tracked = @()
    }
    if ($LASTEXITCODE -ne 0) { $tracked = @() }

    $files = @()
    if ($tracked.Count) {
        foreach ($relative in $tracked) {
            $full = Join-Path $RepoRoot ($relative -replace '/', '\')
            if (-not (Test-Path $full)) { continue }
            $leaf = Split-Path -Leaf $relative
            $isInput = @($BuildInputPatterns | Where-Object { $leaf -like $_ }).Count -gt 0
            # Cargo.lock has no extension in the pattern list; the root manifests are inputs too
            if (-not $isInput) { $isInput = $leaf -in @('Cargo.lock', 'Cargo.toml') }
            if ($isInput) { $files += (Get-Item $full) }
        }
    }

    if ($files.Count -eq 0) {
        # no usable git, or nothing tracked: walk the tree instead of giving up on the check
        $files = @(Get-ChildItem $RepoRoot -File | Where-Object { $_.Name -in @('Cargo.toml', 'Cargo.lock') })
        $files += @(Get-ChildItem (Join-Path $RepoRoot 'crates') -Recurse -File -Include $BuildInputPatterns)
    }
    # a build script is an input in its own right and is already covered by *.rs
    $files = @($files | Sort-Object FullName -Unique)
    if (@($files).Count -eq 0) { throw "no build inputs found under $RepoRoot" }
    $files
}

function Get-NewestBuildInput {
    param([Parameter(Mandatory)][string]$RepoRoot)
    @(Get-BuildInputFiles -RepoRoot $RepoRoot | Sort-Object LastWriteTime -Descending | Select-Object -First 1)[0]
}

function Assert-NothingLeftToCompile {
    <#
    .SYNOPSIS
        Proves the release tree is current by asking cargo, not by comparing timestamps.

    .DESCRIPTION
        `Assert-BinariesAreCurrent` compares every shipped binary against the newest tracked source, which
        is conservative to the point of a false positive: changing one bin's source cannot change another
        bin that does not depend on it, and cargo correctly leaves the second one alone with its old mtime.
        A second build that compiles nothing is the statement we actually want - every target is up to date
        with respect to its own dependency graph - and it still fails loudly when no build has run at all.
    #>
    param([string]$RepoRoot = (Split-Path -Parent $PSScriptRoot))
    $out = & cargo build --workspace --bins --release --manifest-path (Join-Path $RepoRoot 'Cargo.toml') 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        $tail = (($out -split "`r?`n" | Select-Object -Last 8) -join ' / ')
        throw "verification build failed (exit $LASTEXITCODE): $tail"
    }
    $compiled = @($out -split "`r?`n" | Where-Object { $_ -match '^\s*Compiling ' })
    if ($compiled.Count) {
        throw ("the tree was not fully built; a second build still had work to do (`n" +
               ($compiled -join "`n") + "`n). Run the release build again before packaging.")
    }
    return 'all release targets are current'
}

function Assert-BinariesAreCurrent {
    <#
      Every binary that is about to be shipped must be at least as new as the newest build input. The
      comparison is deliberately one-sided and reported with both timestamps: the point is to stop a
      release that packages yesterday's installer, not to police clock skew.
    #>
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][string[]]$Binaries,
        [string]$OwnerHint = 'run cargo build --workspace --bins --release'
    )
    $newest = Get-NewestBuildInput -RepoRoot $RepoRoot
    $considered = @(Get-BuildInputFiles -RepoRoot $RepoRoot).Count
    Write-Host "  build inputs considered: $considered, newest is $($newest.Name) at $($newest.LastWriteTime.ToString('s'))"
    foreach ($binary in $Binaries) {
        if (-not (Test-Path $binary)) { throw "no binary at $binary - $OwnerHint" }
        $item = Get-Item $binary
        if ($item.LastWriteTime -lt $newest.LastWriteTime) {
            throw "$($item.Name) ($($item.LastWriteTime.ToString('s'))) is older than the build input $($newest.FullName.Substring($RepoRoot.Length + 1)) ($($newest.LastWriteTime.ToString('s'))); shipping it would package a binary that does not contain the current checks. $OwnerHint, or point CARGO_TARGET_DIR at the tree that was built."
        }
        Write-Host ("  current           : {0} built {1} sha256={2}" -f $item.Name, $item.LastWriteTime.ToString('s'), (Get-FileHash $item.FullName -Algorithm SHA256).Hash.Substring(0, 16))
    }
    $newest
}
