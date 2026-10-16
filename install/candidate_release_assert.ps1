<#
    candidate_release_assert.ps1 - the judgements a candidate release record has to pass, in one place.

    This file exists so the workflow step and the local simulation run the SAME code. A simulation that
    re-implements the checks would only prove that two implementations agree with each other, which is
    not evidence about the thing that ships.

    What it deliberately does NOT cover, because no local run can: whether the GitHub API answered, with
    which permissions, whether the artifact reached the next job, what the runner environment looked
    like, or whether the workflow was scheduled at all. Those belong to the real candidate run.

    Exit codes: 0 every judgement held; 2 the release record is not a candidate; 3 the asset bytes are
    not the asset the record describes. A judgement failure always exits non-zero on its own terms, never
    by inheriting some earlier command's status.
#>
param(
    [Parameter(Mandatory)][string]$ReleaseJson,
    [Parameter(Mandatory)][string]$Tag,
    [Parameter(Mandatory)][string]$TagSha,
    [string]$JobSha = '',
    [string]$PackageDir = '',
    [string]$ExpectedAssetsFile = '',
    # where to write the digest this observer measured, so a later job with no credentials can compare its
    # own transport against it instead of against something it produced for itself
    [string]$RecordShaTo = ''
)
$ErrorActionPreference = 'Stop'

# The expected asset names come from the same table every other gate reads, so "one file" is stated once
# rather than being copied into a step next to a numeric count that can silently disagree with it. That
# disagreement is not hypothetical: a `-ne 9` survived one round of edits while the name list had already
# become a single entry. Counting the expected list makes the two halves impossible to separate.
if (-not $ExpectedAssetsFile) {
    . (Join-Path $PSScriptRoot 'bundle_layout.ps1')
    # forced into an array: a one-element function result is unwrapped to a bare string by PowerShell, and
    # indexing a string hands back a character - which would quietly turn "the first asset" into "the letter c"
    $expected = @(Get-ReleaseAssetNames)
} else {
    $expected = @(Get-Content $ExpectedAssetsFile | Where-Object { $_.Trim() })
}
Write-Host ("  expected     : {0} asset(s) [{1}]" -f $expected.Count, ($expected -join ', '))

$rel = if ($ReleaseJson -match '^\s*\[') { @($ReleaseJson | ConvertFrom-Json) } else { $ReleaseJson | ConvertFrom-Json }
$fails = 0
function Fail([int]$code, [string]$msg) {
    Write-Host "::error::$msg"
    $script:fails = [Math]::Max($script:fails, $code)
}
function Pass([string]$msg) { Write-Host "  ok   $msg" }

Write-Host '=== candidate release record ==='
Write-Host "  tag        : $Tag"

# ---- the release the tag names, and nothing else -------------------------------------------------
$matches = @($rel | Where-Object { $_.tag_name -eq $Tag })
if ($matches.Count -ne 1) {
    Fail 2 "expected exactly one release for tag '$Tag', found $($matches.Count); a candidate has to be pinpointed"
    exit $fails
}
$one = $matches[0]
if (-not $one.draft) {
    Fail 2 "the release for '$Tag' is not a draft; this judges candidates, not published releases"
    exit $fails
}
Pass "release id=$($one.id) is a draft (prerelease=$($one.prerelease))"

# The tag's own object, not `target_commitish`, which can name a branch that has since moved.
if ($one.tag_name -ne $Tag) { Fail 2 "the release names tag $($one.tag_name) rather than $Tag" }
if (-not $TagSha) { Fail 2 "no commit was resolved for tag '$Tag'" }
Pass "tag $Tag -> $TagSha"

if ($JobSha) {
    if ($TagSha -ne $JobSha) {
        Fail 2 "the checkout is $JobSha but the candidate tag points at $TagSha; the code under test would not be the code being accepted"
        exit $fails
    }
    Pass "checked-out commit equals the tag's commit"
}

# ---- the asset set -------------------------------------------------------------------------------
$assets = @($one.assets)
$names = @($assets | ForEach-Object { $_.name })
$dupes = @($names | Group-Object | Where-Object { $_.Count -gt 1 })
$unknown = @($names | Where-Object { $expected -notcontains $_ })
$absent = @($expected | Where-Object { $names -notcontains $_ })
if ($assets.Count -ne $expected.Count) {
    Fail 2 "expected $($expected.Count) asset(s), found $($assets.Count): $($names -join ', ')"
}
if ($dupes.Count) { Fail 2 "duplicate asset names: $($dupes.Name -join ', ')" }
if ($unknown.Count) { Fail 2 "assets that are not package content: $($unknown -join ', ')" }
if ($absent.Count) { Fail 2 "missing package files: $($absent -join ', ')" }
if ($fails) { exit $fails }
Pass "asset set is exactly: $($names -join ', ')"

foreach ($a in $assets) {
    if ($a.state -ne 'uploaded') { Fail 2 "asset $($a.name) is in state '$($a.state)', not uploaded" }
    if (-not $a.size) { Fail 2 "asset $($a.name) reports no size" }
    if (-not $a.digest) { Fail 2 "asset $($a.name) carries no server-side digest" }
}
if ($fails) { exit $fails }
Pass "every asset is uploaded, sized and digest-bearing"

# ---- the bytes that arrived, against the record ---------------------------------------------------
if ($PackageDir) {
    $have = @(Get-ChildItem $PackageDir -File)
    if ($have.Count -ne $expected.Count) {
        Fail 2 "the downloaded set holds $($have.Count) file(s), expected $($expected.Count)"
        exit $fails
    }
    foreach ($a in $assets) {
        $dest = Join-Path $PackageDir $a.name
        if (-not (Test-Path $dest)) { Fail 3 "$($a.name) was not written"; continue }
        $remote = "$($a.digest)" -replace '^sha256:', ''
        $local = (Get-FileHash $dest -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($local -ne $remote) {
            Fail 3 "asset $($a.name) digest mismatch: server says $remote, downloaded file is $local"
            continue
        }
        $disk = (Get-Item $dest).Length
        if ($a.size -and $disk -ne $a.size) {
            Fail 3 "asset $($a.name) is $disk bytes on disk, the record advertises $($a.size)"
            continue
        }
        Pass ("fetched {0} ({1} bytes, advertised {2}) sha256={3} matches the release record" -f $a.name, $disk, $a.size, $local.Substring(0, 16))
        if ($RecordShaTo -and $a.name -eq $expected[0]) {
            # recorded as the lowercase hex the other job will recompute, and only for the asset that ships
            Set-Content -Path $RecordShaTo -Value $local -Encoding ascii
        }
    }
    if ($fails) { exit $fails }
}

Write-Host '  candidate release record and asset transport accepted'
exit 0
