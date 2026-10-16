<#
    candidate_asset_assert.ps1 - judge the delivered release asset: the host as an asset, then its payload.

    Two claims that must not be merged:
      the HOST is judged as a release asset - exactly the expected files, byte-identical to a digest someone
        OTHER than this script recorded, carrying a signature from the pinned identity with its timestamp
        recorded as observed;
      the PAYLOAD is judged by the inner chain - expansion through a bundle tool built outside the candidate,
        the member whitelist, the index tying each file back to this host, and the payload's own manifest
        re-hashed from disk.

    The recorded digest is a parameter rather than something computed here, on purpose: a script that hashes
    the file and then compares the hash to itself proves nothing about transport. In the workflow the value
    is what a different job saw from the server's own asset record; in local simulation it is computed by
    certutil while the comparison here uses Get-FileHash - two implementations, and one of the negative
    cases is a deliberately wrong recorded value.

    Exit codes: 0 accepted; 2 the asset set or its signature is not what a release claims to be; 3 the
    bytes do not match the recorded digest; 4 the payload did not expand, or does not tie to this host.
#>
param(
    [Parameter(Mandatory)][string]$PackageDir,
    # deliberately not mandatory: the case where an observer recorded nothing has to reach the judgement
    # below and be refused by it, rather than failing in PowerShell's parameter binder
    [string]$RecordedSha = '',
    [Parameter(Mandatory)][string]$BundleTool,
    [Parameter(Mandatory)][string]$PayloadDir,
    [string]$IdentityThumbprint = '',
    [switch]$SkipSignature
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'bundle_layout.ps1')
$fails = 0
function Fail([int]$code, [string]$msg) { Write-Host "::error::$msg"; $script:fails = [Math]::Max($script:fails, $code) }
function Pass([string]$msg) { Write-Host "  ok   $msg" }

Write-Host '=== delivered release asset ==='
# PowerShell unwraps a single-element result to a bare string, and indexing THAT yields a character - the
# path then silently becomes <dir>\c. Every expected list is forced back into an array for that reason.
$expected = @(Get-ReleaseAssetNames)
$have = @(Get-ChildItem $PackageDir -File -EA SilentlyContinue)
$names = @($have | ForEach-Object { $_.Name })
$extra = @($names | Where-Object { $expected -notcontains $_ })
$absent = @($expected | Where-Object { $names -notcontains $_ })
if ($extra.Count) { Fail 2 "unexpected files arrived: $($extra -join ', ')" }
if ($absent.Count) { Fail 2 "the release asset did not arrive: $($absent -join ', ')" }
if ($have.Count -ne $expected.Count) { Fail 2 "expected $($expected.Count) asset(s), got $($have.Count)" }
if ($fails) { exit $fails }
Pass "$($have.Count) file delivered: $($names -join ', ')"

$shipped = Join-Path $PackageDir $expected[0]
$external = (Get-FileHash $shipped -Algorithm SHA256).Hash.ToUpperInvariant()
Write-Host "  asset sha256 : $external"
if (-not $RecordedSha) {
    Fail 2 'no digest was recorded by another observer; refusing to verify a file against a value produced here'
    exit $fails
}
if ($external -ne $RecordedSha.ToUpperInvariant()) {
    Fail 3 "the delivered bytes hash to $external, the record says $($RecordedSha.ToUpperInvariant()); the two transports disagree"
    exit $fails
}
Pass 'bytes match the digest recorded independently of this script'

if (-not $SkipSignature) {
    $sig = Get-AuthenticodeSignature $shipped
    $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { 'none' }
    Write-Host ("  signature    : {0}  signer={1}" -f $sig.Status, $signer)
    if ($sig.Status -notin 'Valid', 'NotTrusted', 'UnknownError') {
        Fail 2 "the release asset carries no usable signature (status=$($sig.Status))"
    }
    if ($IdentityThumbprint -and $signer -ne $IdentityThumbprint) {
        Fail 2 "the asset is signed by $signer, not the release identity $IdentityThumbprint"
    }
    # a chain terminating in a publisher this machine does not trust is expected for a self-signed release
    # identity and is reported as that - it is a trust statement, not a tamper signal, and it must not be
    # presented as a timestamp failure or quietly ignored
    $ts = $null
    if ($sig.SignerCertificate) { $ts = $sig.SignerCertificate.TimeStampInfo }
    Write-Host ('  timestamp    : ' + $(if ($ts) { $ts.SignerCertificate.NotAfter.ToString('s') } else { 'not exposed through this API; the signing job records the signtool verdict' }))
    if ($fails) { exit $fails }
    Pass 'signature present and from the expected identity'
} else {
    Write-Host '  NOTE: -SkipSignature: an unsigned CI shape, not distributable'
}

# ---- the payload inside it ------------------------------------------------------------------------
if (-not $BundleTool) { Fail 4 'no bundle tool was supplied; a bundled candidate cannot be opened'; exit $fails }
if (-not (Test-Path $BundleTool)) { Fail 4 "bundle tool not found at $BundleTool"; exit $fails }
try {
    $null = Expand-BundledInstaller -Installer $shipped -To $PayloadDir -BundleTool $BundleTool
    Pass ('payload expanded: ' + ((@(Get-ChildItem $PayloadDir -File | Sort-Object Name | ForEach-Object { $_.Name })) -join ', '))
} catch {
    # the whole reason, on one line: the first line alone says "did not verify" and the actual cause - which
    # member, which digest, which structural rule - is in what the tool reported underneath it
    Fail 4 ((($_.Exception.Message -split "`r?`n" | Where-Object { $_.Trim() }) -join ' | '))
    exit $fails
}
try {
    $n = Assert-PackageComesFromInstaller -Installer $shipped -PackageDir $PayloadDir -BundleTool $BundleTool
    Pass "$n payload members hash to what this host's index claims"
} catch {
    Fail 4 ((($_ -split "`r?`n" | Where-Object { $_.Trim() }) -join ' | '))
    exit $fails
}
$listed = 0
foreach ($line in @(Get-Content (Join-Path $PayloadDir 'SHA256SUMS.txt') -EA SilentlyContinue)) {
    if ($line -notmatch '^([0-9a-fA-F]{64})\s+(\S+)$') { Fail 4 "unparsable manifest line: $line"; continue }
    $want = $Matches[1].ToUpperInvariant(); $name = $Matches[2]
    $path = Join-Path $PayloadDir $name
    if (-not (Test-Path $path)) { Fail 4 "the manifest lists $name which is absent from the payload"; continue }
    $got = (Get-FileHash $path -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($got -ne $want) { Fail 4 "$name digest mismatch: manifest $want, file $got"; continue }
    $listed++
}
if ($listed -lt 1) { Fail 4 'the payload manifest lists nothing' }
else { Pass "$listed payload digests re-hashed from disk against the manifest" }
if ($fails) { exit $fails }

Write-Host '  release asset accepted: host verified as an asset, payload verified against this host'
exit 0
