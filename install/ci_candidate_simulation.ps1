<#
    ci_candidate_simulation.ps1 - run the candidate workflow's own assertions against a simulated Draft.

    The point of this file is that it does NOT re-implement the judgements. Every scenario below calls the
    same `candidate_release_assert.ps1` / `candidate_asset_assert.ps1` the workflow steps call, through a
    child process, so a pass here is evidence about that code and a fail is reported with the exit code that
    code chose.

    What a local simulation cannot prove, and does not claim to: whether the GitHub API answers, with which
    permissions, whether an artifact actually reaches the next job, what the runner looks like, or whether
    the workflow is dispatched at all. A fabricated release record stands in for the API response only; the
    transport itself is not exercised. The real candidate run is the only evidence for those.

    Exit codes: 0 every scenario behaved as required; 50 at least one did not; 51 the harness could not
    start (a missing artifact or tool is not a pass).
#>
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [Parameter(Mandatory)][string]$Installer,
    [Parameter(Mandatory)][string]$BundleTool,
    [string]$Catsig = '',
    [string]$Work = ''
)
$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'bundle_layout.ps1')
if (-not $Work) { $Work = Join-Path $env:TEMP ('cand-sim-' + (Get-Date).ToString('HHmmss')) }
New-Item -ItemType Directory -Force -Path $Work | Out-Null
if (-not (Test-Path $Installer)) { Write-Host "FAIL(51): no candidate artifact at $Installer"; exit 51 }
if (-not (Test-Path $BundleTool)) { Write-Host "FAIL(51): no bundle tool at $BundleTool"; exit 51 }

$releaseAssert = Join-Path $PSScriptRoot 'candidate_release_assert.ps1'
$assetAssert = Join-Path $PSScriptRoot 'candidate_asset_assert.ps1'
$tag = 'v0.1.0-rc4-simulated'
$tagSha = & git -C $RepoRoot rev-parse HEAD 2>&1
if ($LASTEXITCODE -ne 0) { Write-Host "FAIL(51): cannot resolve a commit to simulate the tag: $tagSha"; exit 51 }
$tagSha = "$tagSha".Trim()

# the package directory the workflow would have built, and the digest recorded by a DIFFERENT tool than the
# assertion uses, so "verified" cannot mean "agreed with itself"
$pkg = Join-Path $Work 'candidate'
New-Item -ItemType Directory -Force -Path $pkg | Out-Null
Copy-Item $Installer (Join-Path $pkg 'cm400-setup.exe') -Force
$payload = Join-Path $Work 'payload'

function Get-CertutilSha([string]$path) {
    $o = & certutil.exe -hashfile $path SHA256 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "certutil could not hash $path : $o" }
    $line = @($o -split "`r?`n" | ?{ $_ -match '^[0-9a-fA-F]{64}$' })
    if (-not $line.Count) { throw "no digest line in certutil output:`n$o" }
    return ($line[0] -replace '\s', '').ToUpperInvariant()
}
function New-ReleaseRecord {
    param(
        [string]$Tag = $tag,
        [bool]$Draft = $true,
        [object[]]$Assets,
        [string]$Id = '900001'
    )
    # `-Assets @()` has to mean "the release carries nothing", so the default is decided by whether the
    # caller bound the parameter at all: an empty array is false in PowerShell, and testing it that way
    # would silently substitute a healthy record for the failure case under test
    if (-not $PSBoundParameters.ContainsKey('Assets')) {
        $src = Join-Path $pkg 'cm400-setup.exe'
        $Assets = @([pscustomobject]@{
                name    = 'cm400-setup.exe'
                id      = 700001
                state   = 'uploaded'
                size    = (Get-Item $src).Length
                digest  = 'sha256:' + (Get-CertutilSha $src).ToLowerInvariant()
            })
    }
    $list = @($Assets | ForEach-Object {
            if ($_ -is [pscustomobject]) { $_ } else { [pscustomobject]$_ }
        })
    return (@([pscustomobject]@{
            tag_name         = $Tag
            id               = $Id
            name             = 'CM400 rc4 (simulated candidate)'
            draft            = $Draft
            prerelease       = $false
            target_commitish = 'main'
            assets           = $list
        }) | ConvertTo-Json -Depth 8 -AsArray)
}

function Run-Assert([string]$name, [string]$script, [hashtable]$params, [int[]]$want, [string]$wantPattern = '') {
    $argList = @('-NoProfile','-ExecutionPolicy','Bypass','-File', $script)
    foreach ($k in $params.Keys) {
        $v = $params[$k]
        if ($v -is [bool]) {
            # a switch parameter cannot take a separate argument token; `-Name:$true` is how it is handed
            # over the command line, and getting this wrong makes the child fail in its binder instead of
            # answering the judgement under test
            $argList += ('-{0}:${1}' -f $k, $(if ($v) { 'true' } else { 'false' }))
        } else {
            $argList += @("-$k", "$v")
        }
    }
    $out = (& pwsh @argList 2>&1) -join "`n"
    $code = $LASTEXITCODE
    $inWant = @($want) -contains $code
    $pat = if ($wantPattern) { $out -match $wantPattern } else { $true }
    $ok = $inWant -and $pat
    $reason = ''
    foreach ($l in ($out -split "`n")) { if ($l -match '::error::') { $reason = ($l -replace '.*::error::','').Trim(); break } }
    if ($reason.Length -gt 96) { $reason = $reason.Substring(0, 96) }
    Write-Host ("  [{0}] {1}: exit={2} want[{3}] {4}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $name, $code, ($want -join '/'), $reason)
    if (-not $ok) { $script:bad++ }
    return $code
}

$script:bad = 0
Write-Host "=== simulated candidate acceptance (artifact: $((Get-Item $Installer).Length)B) ==="
$goodSha = Get-CertutilSha (Join-Path $pkg 'cm400-setup.exe')
$goodJson = New-ReleaseRecord

Write-Host "`nA. the record a candidate has to be"
Run-Assert 'happy-record' $releaseAssert @{ ReleaseJson = $goodJson; Tag = $tag; TagSha = $tagSha; JobSha = $tagSha; PackageDir = $pkg } @(0) | Out-Null
Run-Assert 'already-published-release-refused' $releaseAssert @{ ReleaseJson = (New-ReleaseRecord -Draft $false); Tag = $tag; TagSha = $tagSha; JobSha = $tagSha } @(2) 'not a draft' | Out-Null
Run-Assert 'no-draft-for-tag-refused' $releaseAssert @{ ReleaseJson = (New-ReleaseRecord -Tag 'some-other-tag'); Tag = $tag; TagSha = $tagSha; JobSha = $tagSha } @(2) 'exactly one release' | Out-Null
Run-Assert 'tag-commit-mismatch-refused' $releaseAssert @{ ReleaseJson = $goodJson; Tag = $tag; TagSha = $tagSha; JobSha = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef' } @(2) 'checkout is' | Out-Null
Run-Assert 'two-assets-refused' $releaseAssert @{ ReleaseJson = (New-ReleaseRecord -Assets @(@{ name = 'cm400-setup.exe'; id = 1; state = 'uploaded'; size = 10; digest = 'sha256:aa' }, @{ name = 'notes.md'; id = 2; state = 'uploaded'; size = 10; digest = 'sha256:bb' })); Tag = $tag; TagSha = $tagSha; JobSha = $tagSha } @(2) 'expected 1 asset' | Out-Null
Run-Assert 'zero-assets-refused' $releaseAssert @{ ReleaseJson = (New-ReleaseRecord -Assets @()); Tag = $tag; TagSha = $tagSha; JobSha = $tagSha } @(2) 'asset' | Out-Null
Run-Assert 'duplicate-asset-names-refused' $releaseAssert @{ ReleaseJson = (New-ReleaseRecord -Assets @(@{ name = 'cm400-setup.exe'; id = 1; state = 'uploaded'; size = 10; digest = 'sha256:aa' }, @{ name = 'cm400-setup.exe'; id = 2; state = 'uploaded'; size = 10; digest = 'sha256:bb' })); Tag = $tag; TagSha = $tagSha; JobSha = $tagSha } @(2) 'duplicate' | Out-Null
Run-Assert 'asset-still-uploading-refused' $releaseAssert @{ ReleaseJson = (New-ReleaseRecord -Assets @(@{ name = 'cm400-setup.exe'; id = 1; state = 'new'; size = 10; digest = 'sha256:aa' })); Tag = $tag; TagSha = $tagSha; JobSha = $tagSha } @(2) 'not uploaded' | Out-Null

Write-Host "`nB. the bytes that arrived"
Run-Assert 'happy-transport' $releaseAssert @{ ReleaseJson = $goodJson; Tag = $tag; TagSha = $tagSha; JobSha = $tagSha; PackageDir = $pkg } @(0) 'matches the release record' | Out-Null
$badDigestJson = New-ReleaseRecord -Assets @(@{ name = 'cm400-setup.exe'; id = 1; state = 'uploaded'; size = (Get-Item (Join-Path $pkg 'cm400-setup.exe')).Length; digest = ('sha256:' + ('0' * 64)) })
Run-Assert 'server-digest-mismatch-refused' $releaseAssert @{ ReleaseJson = $badDigestJson; Tag = $tag; TagSha = $tagSha; JobSha = $tagSha; PackageDir = $pkg } @(3) 'digest mismatch' | Out-Null
Run-Assert 'recorded-sha-mismatch-refused' $assetAssert @{ PackageDir = $pkg; RecordedSha = ('0' * 64); BundleTool = $BundleTool; PayloadDir = $payload } @(3) 'two transports disagree' | Out-Null
Run-Assert 'no-recorded-sha-refused' $assetAssert @{ PackageDir = $pkg; RecordedSha = ''; BundleTool = $BundleTool; PayloadDir = $payload } @(2) 'refusing to verify a file against a value produced here' | Out-Null

$dirExtra = Join-Path $Work 'extra-asset'
New-Item -ItemType Directory -Force -Path $dirExtra | Out-Null
Copy-Item $Installer (Join-Path $dirExtra 'cm400-setup.exe') -Force
Set-Content -Path (Join-Path $dirExtra 'release-notes.md') -Value 'not package content' -Encoding ascii
Run-Assert 'extra-file-in-package-refused' $assetAssert @{ PackageDir = $dirExtra; RecordedSha = $goodSha; BundleTool = $BundleTool; PayloadDir = $payload } @(2) 'unexpected files arrived' | Out-Null
$dirEmpty = Join-Path $Work 'missing-asset'
New-Item -ItemType Directory -Force -Path $dirEmpty | Out-Null
Run-Assert 'missing-asset-refused' $assetAssert @{ PackageDir = $dirEmpty; RecordedSha = $goodSha; BundleTool = $BundleTool; PayloadDir = $payload } @(2) 'did not arrive' | Out-Null

Write-Host "`nC. opening the container"
Run-Assert 'happy-asset-and-payload' $assetAssert @{ PackageDir = $pkg; RecordedSha = $goodSha; BundleTool = $BundleTool; PayloadDir = $payload } @(0) 'payload verified against this host' | Out-Null
Run-Assert 'missing-bundle-tool-refused' $assetAssert @{ PackageDir = $pkg; RecordedSha = $goodSha; BundleTool = (Join-Path $Work 'no-such-tool.exe'); PayloadDir = (Join-Path $Work 'p2') } @(4) 'bundle tool not found' | Out-Null
$brokenHost = Join-Path $Work 'broken-host.exe'
Copy-Item $Installer $brokenHost -Force
$bytes = [IO.File]::ReadAllBytes($brokenHost)
$found = Find-Cm400AppendEnd $brokenHost
# cut the host just past the trailer so the bundle can no longer be located, exactly as a truncated upload would
$keep = $found.end - 4
[IO.File]::WriteAllBytes($brokenHost, $bytes[0..($keep - 1)])
$dirBroken = Join-Path $Work 'broken-pkg'
New-Item -ItemType Directory -Force -Path $dirBroken | Out-Null
Copy-Item $brokenHost (Join-Path $dirBroken 'cm400-setup.exe') -Force
# The truncated host is also unsigned now, because truncating drops the certificate table; the judgement
# under test here is the unpacker, so the signature leg is switched off explicitly rather than letting one
# refusal stand in for another.
Run-Assert 'unreadable-payload-refused' $assetAssert @{ PackageDir = $dirBroken; RecordedSha = (Get-CertutilSha (Join-Path $dirBroken 'cm400-setup.exe')); BundleTool = $BundleTool; PayloadDir = (Join-Path $Work 'p3'); SkipSignature = $true } @(4) 'bundle' | Out-Null

Write-Host "`nD. the gate scripts still refuse what they always refused, on the final artifact"
$payForGates = Join-Path $Work 'gates-payload'
$null = Expand-BundledInstaller -Installer (Join-Path $pkg 'cm400-setup.exe') -To $payForGates -BundleTool $BundleTool
$daemon = Join-Path $payForGates 'cm400d.exe'
$db = [IO.File]::ReadAllBytes($daemon); $db[[int]($db.Length / 2)] = $db[[int]($db.Length / 2)] -bxor 0x01
[IO.File]::WriteAllBytes($daemon, $db)
if ((Get-FileHash $daemon).Hash -eq (Get-FileHash (Join-Path $payload 'cm400d.exe')).Hash) {
    Write-Host '  [FAIL] the payload mutation did not take effect'; $script:bad++
}
$vp = & (Join-Path $pkg 'cm400-setup.exe') verify-package (Join-Path $payForGates 'cm400.inf') --staged 2>&1 | Out-String
Write-Host ("  [{0}] tampered payload refused by verify-package --staged: exit={1}" -f $(if ($LASTEXITCODE -ne 0 -and $vp -match 'has SHA-256') { 'PASS' } else { 'FAIL' }), $LASTEXITCODE)
if (-not ($LASTEXITCODE -ne 0 -and $vp -match 'has SHA-256')) { $script:bad++ }

Write-Host ''
if ($script:bad) { Write-Host "== simulated acceptance: $script:bad scenario(s) did not behave as required =="; exit 50 }
Write-Host '== simulated acceptance: every scenario behaved as required =='
Write-Host "  work kept for inspection: $Work"
exit 0
