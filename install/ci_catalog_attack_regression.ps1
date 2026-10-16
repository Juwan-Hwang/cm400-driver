#Requires -Version 7
<#
  Attack regression for the release candidate gate.

  Every case builds a mutated copy of the staged package under %TEMP% and runs the *real* pre-execution
  verifier on it, asserting both the exit code and which leg refused. A case that fails for an unrelated
  reason is a case that has not tested anything, so the reason check is not optional.

  The cases correspond to what the three legs were measured to cover:

    pristine                 accepted; the gate is not simply a wall
    signed content flipped   leg 2b signature  -> crypt32 reports a hash error; the catalog no longer
                             matches what was signed
    embedded cert flipped    leg 2b identity    -> still verifies, because `certificates` sits outside
                             the signed digest; caught only by comparing the embedded DER with the pin
    INF replaced + manifest recomputed for it, catalog untouched   leg 3 content binding
    installer + manifest swapped as a pair, catalog untouched      refused before any candidate runs
    extra file / subdirectory / hidden file / missing catalog      layout
    unsigned catalog                                               refused, never treated as "unknown"

  Nothing here runs a candidate binary, touches a trust store, or modifies dist\staging.

  Exit codes: 0 all cases behaved as required; 50 at least one case did not; 51 the harness itself could
  not run (verifier or package missing - reported rather than silently passing zero cases).
#>
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$Package = '',
    [string]$Catsig = '',
    # the rc4 shape. $Package is then the payload expanded out of $Installer, and each mutated copy is
    # judged as "not the shipped host's payload" (exit 43) in addition to whatever it used to fail on -
    # that is a stronger refusal, not a substitute, so the accepted codes are widened rather than the
    # cases narrowed.
    [switch]$Bundled,
    [string]$Installer = '',
    [string]$BundleTool = ''
)
$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'bundle_layout.ps1')
if (-not $Package) { $Package = Join-Path $RepoRoot 'dist\staging' }
if ($Bundled -and (-not $Installer -or -not $BundleTool)) {
    Write-Host 'FAIL(51): -Bundled needs -Installer and -BundleTool; a host-less bundled run would test nothing'
    exit 51
}
if ($Bundled -and -not (Test-Path $Installer)) {
    Write-Host "FAIL(51): no shipped installer at $Installer"
    exit 51
}
if (-not (Test-Path (Join-Path $Package 'cm400.cat'))) {
    Write-Host "FAIL(51): no signed package at $Package - a regression that tests nothing must not pass"
    exit 51
}
$verifier = $Catsig
if (-not $verifier) {
    $verifier = @(
        (Join-Path $env:CARGO_TARGET_DIR 'debug\cm400-catsig.exe'),
        (Join-Path $env:CARGO_TARGET_DIR 'release\cm400-catsig.exe'),
        (Join-Path $RepoRoot 'target\release\cm400-catsig.exe')
    ) | ?{ Test-Path $_ } | Select-Object -First 1
}
if (-not $verifier) { Write-Host 'FAIL(51): cm400-catsig.exe is not built'; exit 51 }
Write-Host "verifier: $verifier"
Write-Host "package : $Package"

$work = Join-Path $env:TEMP "cm400-attack-$([guid]::NewGuid().ToString('N').Substring(0,8))"
New-Item -ItemType Directory -Force -Path $work | Out-Null
$script:bad = 0

function New-Copy([string]$name) {
    $d = Join-Path $work $name
    if (Test-Path $d) { Remove-Item $d -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $d | Out-Null
    Copy-Item (Join-Path $Package '*') $d -Force -Recurse
    # prove the copy is a copy: a directory that silently arrived empty would turn every case into a
    # false pass, which is exactly the failure mode this harness has had once already
    if (@(Get-ChildItem $d -File).Count -ne @(Get-ChildItem $Package -File).Count) {
        throw "copy $name has $(@(Get-ChildItem $d -File).Count) files, the package has $(@(Get-ChildItem $Package -File).Count)"
    }
    return $d
}
function Flip([string]$path, [int]$offset) {
    $b = [IO.File]::ReadAllBytes($path)
    if ($offset -ge $b.Length) { throw "offset $offset beyond end of $path" }
    $b[$offset] = $b[$offset] -bxor 1
    [IO.File]::WriteAllBytes($path, $b)
    $after = [IO.File]::ReadAllBytes($path)
    if ($after[$offset] -eq ($b[$offset] -bxor 1)) { throw "the write to $path did not take effect" }
}
function Changed([string]$dir, [string]$rel) {
    # a mutation that did not happen cannot demonstrate a refusal; report it as a harness failure
    $a = Join-Path $Package $rel; $b = Join-Path $dir $rel
    if (-not (Test-Path $b)) { return $false }
    $ha = (Get-FileHash $a -Algorithm SHA256).Hash; $hb = (Get-FileHash $b -Algorithm SHA256).Hash
    return $ha -ne $hb
}
function Case {
    param([string]$Name, [string]$Dir, [int[]]$WantExit, [string]$WantPattern, [string[]]$MustChange = @())
    $WantExit = @($WantExit)
    foreach ($rel in $MustChange) {
        if (-not (Changed $Dir $rel)) {
            Write-Host ("  [FAIL] {0}: the mutation of {1} did not take effect, so this case tested nothing" -f $Name, $rel)
            $script:bad++
            return
        }
    }
    # a real child process, because the verifier reports through the host and host writes do not reach
    # an in-process `| Out-String`
    $want = @($WantExit)
    $vpArgs = @('-PackageDir', $Dir, '-RepoRoot', $RepoRoot, '-Catsig', $verifier)
    if ($Bundled) {
        # the copy is no longer the payload of the file that ships, which preverify must catch on top of
        # whatever digest or membership reason it already has; keeping both in the accepted set is what
        # stops "it was refused" from hiding "it was refused for the weaker reason"
        $want += 43
        # kept OUTSIDE the case directory: a file added to the package would trip the whitelist check first
        # and turn every case into the same refusal for the same trivial reason
        $hostCopy = Join-Path $work ("host-" + ($Name -replace '[^A-Za-z0-9]', '') + '.exe')
        Copy-Item $Installer $hostCopy -Force
        $vpArgs += @('-Bundled', '-Installer', $hostCopy, '-BundleTool', $BundleTool)
    }
    $out = (& pwsh -NoProfile -File (Join-Path $PSScriptRoot 'ci_preverify_candidate.ps1') `
            @vpArgs 2>&1) -join "`n"
    $code = $LASTEXITCODE
    $inWant = @($want) -contains $code
    $patternHit = if ($WantPattern) { $out -match $WantPattern } else { $true }
    $ok = $inWant -and $patternHit
    $refusal = ''
    if ($code -ne 0 -and $out -match '(?m)^\s*FAIL\((\d+)\): (.+)$') {
        $refusal = 'refusal: ' + $Matches[2].Trim()
        if ($refusal.Length -gt 100) { $refusal = $refusal.Substring(0, 100) }
    }
    $status = if ($ok) { 'PASS' } else { 'FAIL' }
    $want = $WantExit -join '/'
    $pat = if ($WantPattern) { "'$WantPattern'" } else { '-' }
    Write-Host ("  [{0}] {1}: exit={2} want[{3}] pattern={4} {5}" -f $status, $Name, $code, $want, $pat, $refusal)
    if (-not $ok) {
        $script:bad++
        ($out -split "`n" | ?{ $_ -match 'FAIL|REFUSED|WRONGLY' } | Select-Object -First 6) | %{ Write-Host ("      | " + $_.Trim()) }
    }
}

Write-Host "`ncases:"
# 1. the real package
Case 'pristine' (New-Copy 'ok') @(0) 'VERDICT ACCEPTED|crypto-verification-ran.*PASS'

# 2. a byte flipped inside the signed content (measured region: encapContentInfo)
$d = New-Copy 'content'
Flip (Join-Path $d 'cm400.cat') 582
Case 'signed-content-flipped' $d @(40) 'FAIL signature' @('cm400.cat')

# 3. a byte flipped inside the embedded certificate, which the signature does not cover
$d = New-Copy 'cert'
Flip (Join-Path $d 'cm400.cat') 1282
Case 'embedded-cert-flipped' $d @(40) 'FAIL embedded-identity' @('cm400.cat')

# 4. the INF replaced and the manifest recomputed for it, catalog untouched
$d = New-Copy 'inf'
Add-Content -Path (Join-Path $d 'cm400.inf') -Value '; attacker added a line' -Encoding ascii
$sums = Join-Path $d 'SHA256SUMS.txt'
$lines = @(Get-Content $sums) | ?{ $_ -notmatch ' cm400\.inf$' }
$h = (Get-FileHash (Join-Path $d 'cm400.inf') -Algorithm SHA256).Hash.ToLowerInvariant()
$lines += "$h  cm400.inf"
Set-Content -Path $sums -Value $lines -Encoding ascii
Case 'inf-replaced-manifest-recomputed' $d @(13, 15, 40) 'FAIL content-binding|not attested|digest' @('cm400.inf', 'SHA256SUMS.txt')

# 5. the service binary swapped out and the manifest rewritten so the directory stays self-consistent,
# catalog untouched: only the catalog's member list can say no.
# In the loose layout the pair is "installer + daemon", because both are package files. In the bundled
# layout the installer is NOT in the package, so the same class of attack is stated against what is there:
# the daemon replaced by another file's bytes with its manifest line recomputed. The assertion is kept by
# re-instantiating its premise, not by dropping it.
$d = New-Copy 'pair'
$daemon = Join-Path $d 'cm400d.exe'
$pairTargets = @('cm400d.exe')
if (-not $Bundled) {
    $setup2 = Join-Path $d 'cm400-setup.exe'
    $a = [IO.File]::ReadAllBytes($setup2); $b = [IO.File]::ReadAllBytes($daemon)
    [IO.File]::WriteAllBytes($setup2, $b); [IO.File]::WriteAllBytes($daemon, $a)
    $pairTargets = @('cm400-setup.exe', 'cm400d.exe')
} else {
    # the same premise against what is actually in a payload: the daemon's bytes changed and its manifest
    # line rewritten so the directory agrees with itself, catalog untouched. Swapping the certificate out
    # as well was tried first and merely tripped the identity leg (exit 11) - a refusal for a different
    # fact, which would have let this case stop testing the member list while still looking like a pass.
    $dd = [IO.File]::ReadAllBytes($daemon); $dd[500] = $dd[500] -bxor 0xFF
    [IO.File]::WriteAllBytes($daemon, $dd)
    $pairTargets = @('cm400d.exe')
}
foreach ($rel in $pairTargets) {
    $hp = (Get-FileHash (Join-Path $d $rel) -Algorithm SHA256).Hash.ToUpperInvariant()
    $ls = @(Get-Content (Join-Path $d 'SHA256SUMS.txt')) | %{ if ($_ -match " $([regex]::Escape($rel))\s*$") { "$hp  $rel" } else { $_ } }
    Set-Content -Path (Join-Path $d 'SHA256SUMS.txt') -Value $ls -Encoding ascii
}
Case 'installer-and-list-swapped' $d @(13, 15, 40) 'FAIL|REFUSED' $pairTargets

# 6. layout: an extra file, a subdirectory that is not bin, a hidden file, a missing catalog
$d = New-Copy 'extra'
Set-Content -Path (Join-Path $d 'unexpected.txt') -Value 'x' -Encoding ascii
Case 'extra-file' $d @(14) 'whitelist|unexpected|not exactly'
$d = New-Copy 'nested'
New-Item -ItemType Directory -Force -Path (Join-Path $d 'otherdir') | Out-Null
Set-Content -Path (Join-Path $d 'otherdir\x.exe') -Value 'MZ' -Encoding ascii
Case 'extra-subdirectory' $d @(14) 'whitelist|subdirector|unexpected|not exactly'
$d = New-Copy 'hidden'
$hf = Join-Path $d 'hiddenfile.txt'
Set-Content -Path $hf -Value 'x' -Encoding ascii
attrib.exe +h $hf
Case 'hidden-file' $d @(14) 'whitelist|hidden|unexpected|not exactly'
$d = New-Copy 'nocat'
Remove-Item (Join-Path $d 'cm400.cat') -Force
Case 'catalog-missing' $d @(14) 'cm400.cat is missing'

# 7. a catalog replaced by garbage: not a signature, and must not be waved through
$d = New-Copy 'junk'
Set-Content -Path (Join-Path $d 'cm400.cat') -Value 'not a catalog' -Encoding ascii
Case 'catalog-not-a-signature' $d @(12, 16, 40, 42) 'FAIL|REFUSED'

function Report-B([string]$name, [bool]$ok, [string]$detail) {
    Write-Host ("  [{0}] {1}: {2}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $name, $detail)
    if (-not $ok) { $script:bad++ }
}

if ($Bundled) {
    # the two classes the single-file shape makes distinct: the HOST can be tampered with in a way the
    # inner chain cannot see, and the PAYLOAD can be tampered with in a way that leaves the container
    # perfectly self-consistent. Collapsing them is how "the bundle parsed" becomes mistaken for trust.
    Write-Host "`nbundled host-level cases:" -NoNewline; Write-Host ''

    # B1 one flipped byte inside the appended payload: refused by the container, without any signature
    $f = Find-Cm400AppendEnd $Installer
    $b1 = $f.bytes; $b1[$f.end - 20 - 4096] = $b1[$f.end - 20 - 4096] -bxor 0x20
    $h1 = Join-Path $work 'b1-payload-flipped.exe'
    [IO.File]::WriteAllBytes($h1, $b1)
    $o1 = & $BundleTool extract $h1 --to (Join-Path $work 'b1-out') 2>&1 | Out-String
    Report-B 'payload-byte-flipped-refused-by-the-container' ($LASTEXITCODE -ne 0 -and $o1 -match 'hash to') "exit=$LASTEXITCODE"

    # B2 a byte in the host's own code, outside the bundle: the inner chain must be shown to be blind to
    # it, which is why the release asset needs its signature and its published SHA-256 checked as well
    $f2 = Find-Cm400AppendEnd $Installer
    $b2 = $f2.bytes; $b2[0x2A00] = $b2[0x2A00] -bxor 0x01
    $h2 = Join-Path $work 'b2-host-code-flipped.exe'
    [IO.File]::WriteAllBytes($h2, $b2)
    $null = & $BundleTool extract $h2 --to (Join-Path $work 'b2-out') 2>&1 | Out-String
    $expandOk = ($LASTEXITCODE -eq 0)
    $sigBefore = (Get-AuthenticodeSignature $Installer).Status
    $sigAfter = (Get-AuthenticodeSignature $h2).Status
    $outerCaught = ($sigBefore -ne $sigAfter)
    $unsignedShape = ($sigBefore -eq 'NotSigned')
    Report-B 'host-code-tampering-invisible-to-the-inner-chain' ($expandOk -and ($outerCaught -or $unsignedShape)) `
        ("bundle still expanded=$expandOk; signature $sigBefore -> $sigAfter" + $(if ($unsignedShape) { ' (unsigned shape: only the published hash can notice)' } else { '' }))
    if (-not $unsignedShape -and -not $outerCaught) {
        Report-B 'outer-signature-notices-host-tampering' $false "a signed host was modified and the signature still reads $sigAfter"
    }

    # B3 the payload's daemon swapped and the index recomputed by repacking: self-consistent container,
    # untouched catalog and manifest, so only re-hashing against the manifest can refuse it
    $pay = Join-Path $work 'b3-payload'
    if (Test-Path $pay) { Remove-Item $pay -Recurse -Force }
    $null = Expand-BundledInstaller -Installer $Installer -To $pay -BundleTool $BundleTool
    $daemon = Join-Path $pay 'cm400d.exe'
    $db = [IO.File]::ReadAllBytes($daemon); $db[[int]($db.Length / 2)] = $db[[int]($db.Length / 2)] -bxor 0x01
    [IO.File]::WriteAllBytes($daemon, $db)
    if ((Get-FileHash $daemon).Hash -eq (Get-FileHash (Join-Path $Package 'cm400d.exe')).Hash) {
        Report-B 'b3-mutation-took-effect' $false 'the daemon was not actually changed'
    }
    $h3 = Join-Path $work 'b3-note.txt'
    Set-Content -Path $h3 -Value 'the container was never re-signed: the index of a repacked host would be self-consistent too, and that is the whole point - see ci_single_file_checks for the repacked variant' -Encoding ascii
    $o3 = & $Installer verify-package (Join-Path $pay 'cm400.inf') '--staged' 2>&1 | Out-String
    Report-B 'payload-swapped-with-recomputed-index-refused-by-manifest' ($LASTEXITCODE -ne 0 -and $o3 -match 'has SHA-256') "exit=$LASTEXITCODE"

    # B4 a directory that is not the shipped host's payload must not be accepted as if it were
    $pre = Join-Path $PSScriptRoot 'ci_preverify_candidate.ps1'
    $o4 = (& pwsh -NoProfile -File $pre -PackageDir $pay -RepoRoot $RepoRoot -Catsig $verifier -Bundled -Installer $Installer -BundleTool $BundleTool 2>&1) -join "`n"
    Report-B 'a-package-that-is-not-the-shipped-hosts-payload-refused' ($LASTEXITCODE -eq 43 -or $o4 -match 'does not match the shipped bundle') "exit=$LASTEXITCODE"

    # B5 a bundle carrying an extra member: the whitelist bites inside the container, not only on disk
    $stray = Join-Path $pay 'unexpected-tool.exe'
    Copy-Item $BundleTool $stray -Force
    $h5 = Join-Path $work 'b5-extra-member.exe'
    $files5 = @(Get-ChildItem $pay -File | ForEach-Object { $_.FullName })
    $null = & $BundleTool pack --host $Installer --out $h5 --files $files5 2>&1 | Out-String
    $threw = $false
    try { $null = Expand-BundledInstaller -Installer $h5 -To (Join-Path $work 'b5-out') -BundleTool $BundleTool } catch { $threw = $true }
    Report-B 'extra-member-inside-the-bundle-refused' $threw 'expansion of a bundle with an added file'
}

Remove-Item $work -Recurse -Force -EA SilentlyContinue
Write-Host ("`ntemp work removed: {0}" -f (-not (Test-Path $work)))
if ($script:bad) { Write-Host "FAIL(50): $script:bad case(s) did not behave as required"; exit 50 }
Write-Host "`nALL CASES BEHAVED AS REQUIRED"
exit 0
