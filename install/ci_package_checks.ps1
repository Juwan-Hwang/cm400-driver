#Requires -Version 7
<#
  Pure decision helpers for candidate verification, separated from the driver script so they can be
  tested without a catalog, a certificate or a machine state to corrupt.

  Three questions are answered here, each deliberately narrower than "is this package good":

    Test-SignatureStatusAllowed - which PowerShell SignatureStatus values may a signed catalog carry.
      The list is permissive-by-name, not exclusive-by-name: an unlisted status is refused. That matters
      because the enum contains values whose whole meaning is "we could not make sense of this
      signature", and a check that enumerates the failures it thought of today lets every future or
      unexpected value through. `Valid` and `NotTrusted` are the only two accepted, and for different
      reasons: `Valid` means the signature is intact, `NotTrusted` means the signature is intact but
      this machine does not trust the publisher - which is exactly the state a self-signed release
      candidate arrives in on a clean runner. Accepting `NotTrusted` is not a trust decision, because
      the identity comparison against the pinned certificate is a separate check.

    Test-CatalogMember - whether one catalog member proves that one specific file is attested. The
      member's reference tag (its digest) must equal the digest computed from the file we are holding,
      and that alone is the proof. The member's file name is a secondary confirmation: when the catalog
      records one it has to name the same file, and a member whose *name* matches while its *tag* does
      not is a refusal, never a pass. Catalog members produced by makecat for these packages carry a tag
      and an empty file name, so requiring a name would reject valid packages.

    Get-PackageLayoutProblems - what is inside the package directory. Every entry has to be a plain
      top-level file from the whitelist; directories, nested content, reparse points and hidden extras
      are all problems, because a check that lists only `-File` at the top level cannot see what a
      subdirectory hides.
#>

# These helpers are dot-sourced into the scripts that use them, so no Set-StrictMode here: it would leak
# into the caller's scope and change how unrelated variables in that script behave.

# The two statuses a catalog may be accepted under, with the reason each is tolerable.
#
# MEASURED, and this list must not be widened on the basis of it (the maintainer-side release notes (RELEASE-READINESS) §10f):
# a catalog signed by a self-signed code-signing certificate that this machine does not trust reports
# `UnknownError`, not `NotTrusted`, and `SignerCertificate` is still present with the exact DER. A
# catalog whose member file was modified behind an intact catalog reports the same `UnknownError`, so
# the enum cannot separate "intact but untrusted" from "content no longer matches" - which is why
# adding `UnknownError` here would hand the integrity decision to a value that cannot carry it. Every
# modification made *inside* the catalog reported `NotSigned`, so this list errs by refusing, never by
# accepting a damaged package.
# The consequence is a known, recorded defect: on a clean runner this gate rejects a *valid* candidate.
# The fix is to verify the signature with the pinned public key instead of reading a trust verdict out
# of this enum (see §10f for the proposed shape), not to extend the list below.
$script:Cm400AllowedSignatureStatus = @('Valid', 'NotTrusted')

# Locate the pinned-certificate verifier that was built from this repository's source. One
# implementation, because two discovery blocks drifted apart once and turned every package case into a
# spurious refusal. Returns the first existing candidate path, or an empty string when none is built -
# callers must treat that as a refusal, never as a skip.
function Find-Cm400Verifier {
    param([string]$RepoRoot = '')
    $paths = @()
    if ($RepoRoot) { $paths += (Join-Path $RepoRoot 'target\release\cm400-catsig.exe') }
    if ($env:CARGO_TARGET_DIR) {
        $paths += (Join-Path $env:CARGO_TARGET_DIR 'release\cm400-catsig.exe')
        $paths += (Join-Path $env:CARGO_TARGET_DIR 'debug\cm400-catsig.exe')
    }
    if ($RepoRoot) { $paths += (Join-Path $RepoRoot 'target\debug\cm400-catsig.exe') }
    foreach ($p in $paths) {
        if ($p -and (Test-Path -LiteralPath $p -PathType Leaf)) { return $p }
    }
    return ''
}

function Test-SignatureStatusAllowed {
    param([string]$Status)
    return [bool]($script:Cm400AllowedSignatureStatus -contains $Status)
}

function Test-CatalogMember {
    param(
        # one catalog member, with Tag and File as separate fields
        [pscustomobject]$Member,
        # the digest computed from the file on disk, upper-case hex, as the catalog indexes it
        [string]$ExpectedTag,
        # the file this member is supposed to attest
        [string]$ExpectedFile
    )
    if (-not $Member) { return [pscustomobject]@{ matched = $false; why = 'no member supplied' } }

    $tag = ('' + $Member.Tag).Trim().ToUpperInvariant()
    $want = $ExpectedTag.Trim().ToUpperInvariant()
    $name = ('' + $Member.File).Trim()

    if ($tag -ne $want) {
        # the name may match perfectly; without the digest it attests to nothing about this file
        if ($name -and ((Split-Path $name -Leaf) -eq $ExpectedFile)) {
            return [pscustomobject]@{ matched = $false; why = "file name matches but the reference tag does not ($tag != $want)" }
        }
        return [pscustomobject]@{ matched = $false; why = "reference tag $tag != expected $want" }
    }
    if ($name) {
        # normalize both separators and tolerate a recorded relative or full path, but the leaf has to
        # be the file we are attesting
        $leaf = (Split-Path ($name -replace '/', '\') -Leaf)
        if ($leaf -ne $ExpectedFile) {
            return [pscustomobject]@{ matched = $false; why = "reference tag matches but the member names $leaf, not $ExpectedFile" }
        }
    }
    return [pscustomobject]@{ matched = $true; why = "tag $tag" + $(if ($name) { ", named $name" } else { ' (nameless hash-only member)' }) }
}

function Get-PackageLayoutProblems {
    param(
        [string]$Dir,
        [string[]]$ExpectedFiles
    )
    $problems = @()
    if (-not (Test-Path $Dir)) { return @("directory $Dir does not exist") }
    $entries = @(Get-ChildItem $Dir -Force -EA SilentlyContinue)
    foreach ($e in $entries) {
        if ($e.PSIsContainer) { $problems += "a directory is present in the package: $($e.Name)"; continue }
        if ($e.LinkType) { $problems += "a reparse point is present: $($e.Name) ($($e.LinkType))"; continue }
        if ($e.Attributes -band [IO.FileAttributes]::Hidden) { $problems += "a hidden entry is present: $($e.Name)" }
        if ($ExpectedFiles -notcontains $e.Name) { $problems += "an unexpected file is present: $($e.Name)" }
    }
    $present = @($entries | Where-Object { -not $_.PSIsContainer } | ForEach-Object { $_.Name })
    foreach ($want in $ExpectedFiles) {
        if ($present -notcontains $want) { $problems += "expected file is missing: $want" }
    }
    # nested content is only visible with -Recurse; a package must be a flat set of files
    $nested = @(Get-ChildItem $Dir -Force -Recurse -EA SilentlyContinue | Where-Object { $_.FullName -ne (Join-Path $Dir $_.Name) })
    if ($nested.Count) {
        $problems += "$($nested.Count) nested item(s) exist under the package directory (e.g. $($nested[0].FullName))"
    }
    return @($problems | Select-Object -Unique)
}
