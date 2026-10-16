<#
    ci_single_file_checks.ps1 - the gates that only exist because the release is one file.

    What a directory-shaped release got for free - "these are the files, there are no others" - has to be
    asserted explicitly once the files live inside an executable. This script checks the container, and it
    checks that a wrong container is refused in ways that do not depend on anyone trusting a signature.

    The cases:
      1  a good artifact expands to exactly the release member set, and the expanded bytes hash to what
         the shipped index claims
      2  one flipped byte inside the appended payload is refused, and nothing is written
      3  a broken index (mutated manifest region) is refused at read time
      4  a stripped trailer is refused rather than treated as "no bundle"
      5  a bundle carrying an extra member is refused by the whitelist, not shipped
      6  a payload whose daemon disagrees with the release manifest is refused by the installer even
         though the bundle index is perfectly self-consistent - the case where every structural check
         passes and only re-hashing catches it

    Case 6 needs the signed layout (a catalog and a manifest to disagree with), so on an unsigned CI build
    it reports that it was skipped, with the reason, instead of passing silently.
#>
param(
    [Parameter(Mandatory)][string]$Installer,
    [Parameter(Mandatory)][string]$BundleTool,
    [Parameter(Mandatory)][string]$Work,
    # an unpacked host to build the repack negatives onto, so a negative never nests two bundles
    [string]$HostExe = '',
    [string]$PayloadDir = '',
    [switch]$NoCatalog
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'bundle_layout.ps1')

$fails = 0
function Step($name, [scriptblock]$body) {
    try {
        & $body
        Write-Host "  ok   $name"
    } catch {
        $script:fails++
        Write-Host "  FAIL $name"
        ($_.Exception.Message -split "`r?`n") | ForEach-Object { Write-Host "       $_" }
    }
}
function Want-Fail($what, [scriptblock]$body) {
    <#
    For a refusal that arrives as a thrown command (a helper that `throw`s). Note what this is NOT for:
    an external tool exiting non-zero is the success case, and wrapping that in Want-Fail inverts the
    verdict - the tool refuses, nothing throws, and the gate reports "did not happen". Those cases assert
    on the exit code directly.
    #>
    $threw = $false
    try { & $body } catch { $threw = $true }
    if (-not $threw) { throw "$what did not happen" }
}

if (-not (Test-Path $Installer)) { throw "no installer at $Installer" }
$expected = Get-ExpectedBundleMembers -NoCatalog:$NoCatalog
Write-Host "=== single-file bundle gates ($((Get-Item $Installer).Length) bytes, $($expected.Count) expected members) ==="

# Locate a trailer by its magic rather than assuming it ends the file: on a signed artifact the last bytes
# belong to the certificate table, and a mutation aimed at "end minus something" would then hit the
# signature and prove nothing about the container.
function Find-AppendEnd([string]$path) {
    $bytes = [IO.File]::ReadAllBytes($path)
    $magic = [Text.Encoding]::ASCII.GetBytes('CM400BD1')
    for ($i = $bytes.Length - 8; $i -ge 0; $i--) {
        $hit = $true
        for ($j = 0; $j -lt 8; $j++) { if ($bytes[$i + $j] -ne $magic[$j]) { $hit = $false; break } }
        if ($hit) { return @{ end = $i + 8; bytes = $bytes } }
    }
    throw "no bundle trailer found in $path"
}

$pkg = Join-Path $Work 'expanded'
Step 'expands to exactly the release member set' {
    $null = Expand-BundledInstaller -Installer $Installer -To $pkg -BundleTool $BundleTool -Expected $expected
    $names = @(Get-ChildItem $pkg -File | ForEach-Object { $_.Name } | Sort-Object)
    $want = @($expected | Sort-Object)
    if (Compare-Object $names $want) { throw "member set drifted: $($names -join ', ')" }
} | Out-Null

Step 'expanded bytes are the bytes the shipped index claims' {
    $n = Assert-PackageComesFromInstaller -Installer $Installer -PackageDir $pkg -BundleTool $BundleTool
    if ($n -lt 1) { throw 'the index named nothing' }
} | Out-Null

Step 'one flipped payload byte is refused, with nothing written' {
    $found = Find-AppendEnd $Installer
    $bytes = $found.bytes
    # 4 KiB back from the end of the appendable region is member data on a bundle of this size: the
    # trailer is 20 bytes and the manifest a few hundred
    $at = $found.end - 20 - 4096
    $bytes[$at] = $bytes[$at] -bxor 0x20
    $copy = Join-Path $Work 'flipped.exe'
    [IO.File]::WriteAllBytes($copy, $bytes)
    $out = Join-Path $Work 'flipped-out'
    $e = & $BundleTool extract $copy --to $out 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) { throw "accepted a mutated payload bundle: $e" }
    if ($e -notmatch 'hash to') { throw "refused without naming the digest: $e" }
    if (Test-Path $out) {
        $landed = @(Get-ChildItem $out -File).Count
        if ($landed -ne 0) { throw "a refused extraction left $landed file(s) on disk" }
    }
} | Out-Null

Step 'a corrupted index is refused at read time' {
    $found = Find-AppendEnd $Installer
    $bytes = $found.bytes
    # the manifest length sits 8..12 bytes before the end of the appendable region; blowing it up makes
    # every later offset meaningless, and the reader must say so instead of reading past the end
    $o = $found.end
    $bytes[$o - 12] = 0xFF
    $bytes[$o - 11] = 0xFF
    $bytes[$o - 10] = 0xFF
    $bytes[$o - 9] = 0xFF
    $copy = Join-Path $Work 'badindex.exe'
    [IO.File]::WriteAllBytes($copy, $bytes)
    $r = & $BundleTool list $copy 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) { throw "accepted a corrupted index: $r" }
} | Out-Null

Step 'a stripped trailer is refused, not treated as no bundle' {
    $copy = Join-Path $Work 'stripped.exe'
    $bytes = [IO.File]::ReadAllBytes($Installer)
    $keep = $bytes.Length - 20 - 1
    [IO.File]::WriteAllBytes($copy, $bytes[0..$keep])
    $o = & $BundleTool list $copy 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) { throw "a host with no trailer was accepted: $o" }
} | Out-Null

if ($PayloadDir -and (Test-Path $PayloadDir)) {
    Step 'a bundle carrying an extra member is refused by the whitelist' {
        $src = Get-ChildItem $PayloadDir -File | Select-Object -ExpandProperty FullName
        $stray = Join-Path $Work 'cm400-bundle.exe'
        Copy-Item $BundleTool $stray -Force
        $packed = Join-Path $Work 'withextra.exe'
        $files = @(@($src) + $stray)
        $null = & $BundleTool pack --host $BundleTool --out $packed --files $files 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { throw "could not build the negative: pack failed" }
        $null = Want-Fail 'the member-set whitelist' {
            $null = Expand-BundledInstaller -Installer $packed -To (Join-Path $Work 'withextra-out') -BundleTool $BundleTool -Expected $expected
        }
    } | Out-Null

    Step 'an index-consistent payload that disagrees with the release manifest is refused' {
        if (-not (Test-Path (Join-Path $PayloadDir 'SHA256SUMS.txt'))) {
            Write-Host '       skipped: this shape carries no manifest or catalog, so there is nothing for a'
            Write-Host '       payload to disagree with. The signed build is what exercises this case.'
            return
        }
        $tampered = Join-Path $Work 'payload-tampered'
        if (Test-Path $tampered) { Remove-Item $tampered -Recurse -Force }
        Copy-Item $PayloadDir $tampered -Recurse
        $daemon = Join-Path $tampered 'cm400d.exe'
        $b = [IO.File]::ReadAllBytes($daemon)
        $b[[int]($b.Length / 2)] = $b[[int]($b.Length / 2)] -bxor 0x01
        [IO.File]::WriteAllBytes($daemon, $b)
        $exe = Join-Path $Work 'index-consistent-but-wrong.exe'
        $files = @(Get-ChildItem $tampered -File | ForEach-Object { $_.FullName })
        $base = if ($HostExe -and (Test-Path $HostExe)) { $HostExe } else {
            Write-Host '       note: no -HostExe, so the negative is built on the shipped host and carries'
            Write-Host '       two appended bundles; the reader still locates the last one, which is what a'
            Write-Host '       real tamper would look like, but the cleaner form is preferred.'
            $Installer
        }
        $null = & $BundleTool pack --host $base --out $exe --files $files 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { throw "could not build the negative" }
        # the bundle index verified and the files landed; only the release manifest can say no. `--staged`
        # is what lets the installer apply the staged coverage rule to a payload directory instead of
        # demanding a host file that legitimately is not inside it
        $out = Join-Path $Work 'tampered-package'
        $null = Expand-BundledInstaller -Installer $exe -To $out -BundleTool $BundleTool -Expected $expected
        $v = & $Installer verify-package (Join-Path $out 'cm400.inf') --staged 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) { throw "the installer accepted a daemon its own manifest does not describe:`n$v" }
        if ($v -notmatch 'has SHA-256') {
            throw "refused, but not by naming the digest that disagrees (exit $LASTEXITCODE):`n$v"
        }
        # say which judgement refused, because an unsigned build refuses via the missing catalog and that
        # is a different claim from the digest disagreement the signed build exercises
        ($v -split "`r?`n" | ?{ $_ -match 'digests match|manifest attested' } | Select-Object -First 2) | ForEach-Object { Write-Host ("       " + $_.Trim()) }
    } | Out-Null
} else {
    Write-Host '  note  no -PayloadDir given: the two repack-based negatives were not run'
}

Write-Host ''
if ($fails) {
    Write-Host "== single-file bundle gates: $fails case(s) FAILED =="
    exit 1
}
Write-Host '== single-file bundle gates: all cases passed =='
# an explicit success code, because `pwsh -File` hands the process the exit code of the last native
# command - and the last one here is a refusal this gate provoked on purpose. Measured in cloud CI: every
# case passed and the step still failed on the tampered payload's own exit code.
exit 0
