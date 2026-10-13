#Requires -Version 7
<#
  Pre-execution verification of a release candidate, using only the operating system's own
  cryptographic APIs. Nothing from the package is executed here, which is the whole reason this file
  exists.

  Why the previous arrangement was not enough: `cm400-setup.exe verify-package` does answer the right
  questions, but it answers them about *itself*. If somebody replaced the installer and the digest list
  together while leaving the original `cm400.cat` untouched, the replaced binary was free to report
  "membership OK", and that report was the only evidence the pipeline had. Verification must sit outside
  the trust boundary of the thing being verified.

  What is proven here, in order, before any candidate code runs:

  1. the shipped `cm400.cer` is byte-for-byte the pinned publishing identity recorded in this
     repository - DER SHA-256 and SHA-1 both read from the repo, never from the package;
  2. the catalog carries a signature whose embedded signer certificate *is* that certificate. crypt32
     hands us the signer without building a chain, so this works on a machine that has never seen the
     identity, which a self-signed release model requires;
  3. `cm400.inf` and `SHA256SUMS.txt` are members of that catalog file, read directly out of it with
     CryptCATOpen/CryptCATEnumerateMember and compared against digests computed locally. Membership is
     what ties the digest list to the signature: replace the list and its hash stops being a member of
     the signed catalog, so it attests to nothing;
  4. the folder holds exactly the nine whitelisted files and every SHA-256 in that catalog-attested list
     matches the bytes on disk.

  Why this is sufficient without a purchased certificate: tampering with the catalog breaks (2) or (4);
  re-signing it requires the private key, which is held offline and is in neither the repository, the
  package, nor CI. "Installer and digest list both replaced, catalog untouched" - the case that used to
  slip through - fails at (3), before the replaced binary is trusted with anything.

  Two operating-system details worth recording, because both were measured rather than assumed:
  the catalog functions are exported by `wintrust.dll` (linking against Crypt32.lib is what the headers
  suggest, but there is no cryptcat.dll on this OS and its exports are missing from crypt32.dll), and an
  `Add-Type` in-memory assembly cannot resolve native DLLs at all - its base directory is null, so the
  first P/Invoke dies inside Path.Combine. That is why the interop here is compiled to a real file.

  Exit codes: 0 verified; 11 the certificate is not the pinned identity; 12 the catalog signature is not
  from that identity or is broken; 13 catalog membership not proven; 14 the file set is not exactly the
  whitelist; 15 digest mismatch; 16 the OS catalog API could not be consulted (reported as a failure,
  never waved through); 40 cryptographic verification against the pinned certificate refused the
  package; 41 the wrong-key differential did not refuse; 42 the verifier binary was unavailable.

  Which leg decides what, and why it had to be split this way. `Get-AuthenticodeSignature` is now a
  diagnostic line only: measured on this machine, a catalog whose signature is intact but whose publisher
  this machine does not trust reports `UnknownError`, which is the same value a catalog reports when its
  signed content no longer matches - so that enum cannot carry an integrity verdict (docs
  RELEASE-READINESS.md §10f). Integrity is decided by (2b), which asks crypt32 to verify the signature
  with the pinned certificate itself, in a process-local memory store, with no trust store involved;
  identity is decided by comparing the certificate *embedded in the catalog* with the pinned DER, because
  the message's `certificates` set is outside the signed digest and a verification call handed the
  certificate from the store we supplied (measured: flipping a byte there leaves leg 2b passing and is
  caught only by that comparison). Content binding is decided by (3), which recomputes each file's
  catalog digest and requires the identifier set to match exactly.
#>
param(
    [Parameter(Mandatory = $true)][string]$PackageDir,
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    # cm400-catsig.exe, built by the acceptance job from this repository. It is not part of the package
    # being verified, which is what keeps the verification outside the candidate's own trust boundary.
    [string]$Catsig = ''
)

$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'ci_package_checks.ps1')
$script:exitCode = 0
$script:checks = @()

function Note([string]$name, [bool]$ok, [string]$detail) {
    $script:checks += [pscustomobject]@{ check = $name; ok = $ok; detail = $detail }
    Write-Host ("  [{0}] {1} : {2}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $name, $detail)
}
function Fail([int]$code, [string]$msg) {
    Write-Host "  FAIL($code): $msg"
    # first failure wins, so a wrong-identity package is not reported as a digest problem
    if (-not $script:exitCode) { $script:exitCode = $code }
}

if (-not ('Cm400CatInterop' -as [type])) {
    $src = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class Cm400CatInterop
{
    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CryptCATOpen(string pwszFileName, int fdwOpenFlags, IntPtr hProv,
        uint dwEffectiveID, uint fReserved);

    [DllImport("wintrust.dll", SetLastError = true)]
    static extern IntPtr CryptCATEnumerateMember(IntPtr hCatalog, IntPtr prevMember);

    [DllImport("wintrust.dll", SetLastError = true)]
    static extern bool CryptCATClose(IntPtr hCatalog);

    /// The member ids stored inside this catalog file, read directly.
    ///
    /// CryptCATAdminEnumCatalogFromHash is deliberately not used: it only searches catalogs registered
    /// in the system catalog database, so an uninstalled candidate package would look empty and a clean
    /// runner would fail a valid package. CRYPTCAT_MEMBER on x64 is DWORD cbStruct, padding, then
    /// pwszReferenceTag and pwszFileName; nothing past those two fields is read, so the rest of the
    /// layout cannot be misinterpreted.
    public static string[] MemberIds(string catPath, out string error)
    {
        error = "";
        if (!Environment.Is64BitProcess)
        {
            error = "this reader assumes the x64 CRYPTCAT_MEMBER layout";
            return new string[0];
        }
        IntPtr hcat = CryptCATOpen(catPath, 0, IntPtr.Zero, 0, 0);
        if (hcat == IntPtr.Zero || hcat == new IntPtr(-1))
        {
            error = "CryptCATOpen failed, win32=" + Marshal.GetLastWin32Error();
            return new string[0];
        }
        var list = new List<string>();
        IntPtr prev = IntPtr.Zero;
        for (int guard = 0; guard < 4096; guard++)
        {
            IntPtr m = CryptCATEnumerateMember(hcat, prev);
            if (m == IntPtr.Zero) { break; }
            prev = m;
            string tag = Marshal.PtrToStringUni(Marshal.ReadIntPtr(m, 8));
            string file = Marshal.PtrToStringUni(Marshal.ReadIntPtr(m, 16));
            if (string.IsNullOrEmpty(tag)) { continue; }
            list.Add(tag + "\t" + (file ?? ""));
        }
        CryptCATClose(hcat);
        return list.ToArray();
    }
}
'@
    # compile to disk: an in-memory Add-Type assembly has no base directory, and its native DLL resolver
    # calls Path.Combine(null, ...) before any of our P/Invokes can run
    $asm = Join-Path $env:TEMP 'cm400-cat-interop.dll'
    Remove-Item $asm -Force -EA SilentlyContinue
    try {
        Add-Type -Language CSharp -TypeDefinition $src -OutputAssembly $asm -ErrorAction Stop
        Add-Type -Path $asm -ErrorAction Stop
    }
    catch {
        Write-Host "  FAIL(16): the interop helper could not be compiled or loaded: $($_.Exception.Message)"
        exit 16
    }
}

$PackageDir = (Resolve-Path $PackageDir).Path
Write-Host '=== candidate pre-execution verification (no candidate code is run here) ==='
Write-Host "  package : $PackageDir"

# ---- 1. the shipped certificate must be the identity this repository pins ---------------------
$wantThumb = $null
foreach ($line in @(Get-Content (Join-Path $RepoRoot 'install\cm400-release.thumbprint.txt') -EA SilentlyContinue)) {
    if ($line -match '^\s*thumbprint\s*=\s*([0-9A-Fa-f]{40})\s*$') { $wantThumb = $Matches[1].ToUpperInvariant() }
}
$wantDer = $null
foreach ($line in @(Get-Content (Join-Path $RepoRoot 'install\cm400-release.sha256.txt') -EA SilentlyContinue)) {
    if ($line -match '^\s*sha256_der\s*=\s*([0-9A-Fa-f]{64})\s*$') { $wantDer = $Matches[1].ToUpperInvariant() }
}
if (-not $wantThumb -or -not $wantDer) {
    Note 'repository-pins-readable' $false 'the pin files in this checkout are unreadable'
    Fail 11 'the repository pins could not be read; refusing to verify against nothing'
}

$cer = $null
try { $cer = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new((Join-Path $PackageDir 'cm400.cer')) }
catch { Note 'certificate-is-pinned-identity' $false "cm400.cer cannot be parsed: $($_.Exception.Message)"; Fail 11 'cm400.cer is not a readable certificate' }
if ($cer) {
    if ($cer.HasPrivateKey) { Fail 11 'the shipped certificate carries a private key' }
    $der = [BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($cer.RawData)).Replace('-', '')
    $okCer = ($der -eq $wantDer) -and ($cer.Thumbprint.ToUpperInvariant() -eq $wantThumb)
    Note 'certificate-is-pinned-identity' $okCer "DER SHA-256 $($der.Substring(0,16))vs$($wantDer.Substring(0,16)) SHA-1 $($cer.Thumbprint.Substring(0,8))vs$($wantThumb.Substring(0,8))"
    if (-not $okCer) { Fail 11 'the shipped certificate is not the pinned publishing identity' }
    $eku = @()
    foreach ($ext in $cer.Extensions) {
        if ($ext -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            $eku = @($ext.EnhancedKeyUsages | ForEach-Object { $_.Value })
        }
    }
    Note 'certificate-has-code-signing-eku' ($eku -contains '1.3.6.1.5.5.7.3.3') "usages=[$($eku -join ', ')]"
    if ($eku -notcontains '1.3.6.1.5.5.7.3.3') { Fail 11 'the pinned identity is defined by the code-signing EKU and this certificate lacks it' }
    if ($cer.NotAfter -lt (Get-Date)) { Fail 11 "the certificate expired $($cer.NotAfter.ToString('s'))" }
}

# ---- 2. what the machine's own signature check thinks, as information -------------------------
$catPath = Join-Path $PackageDir 'cm400.cat'
if (Test-Path $catPath) {
    $sig = Get-AuthenticodeSignature $catPath
    # Recorded, never decisive. The allowed-status list stays in place as an observation (and as a
    # refusal for a package that has no signature at all), but the verdict on integrity comes from 2b.
    $statusOk = Test-SignatureStatusAllowed -Status "$($sig.Status)"
    Note 'catalog-signature-status-diagnostic' $statusOk "status=$($sig.Status), allowed=[$($script:Cm400AllowedSignatureStatus -join ', ')] - informational only"
    $signer = $sig.SignerCertificate
    Note 'catalog-signer-visible-to-powershell' ([bool]$signer) $(if ($signer) { "signer=$($signer.Thumbprint.Substring(0,8)) subject=$($signer.Subject)" } else { 'PowerShell recovered no signer certificate from this catalog' })
    if (-not $signer -and -not $statusOk) {
        # an absent signature is still an absent signature: refusing here costs nothing, because the
        # crypto leg below would refuse it too
        Fail 12 "the catalog carries no verifiable signature (status=$($sig.Status))"
    }
} else {
    Note 'catalog-present' $false 'cm400.cat is missing'
    Fail 14 'cm400.cat is missing'
}

# ---- 2b. verify the signature with the pinned certificate, trust stores uninvolved --------------
if (Test-Path $catPath) {
    $verifier = $Catsig
    if (-not $verifier -or -not (Test-Path -LiteralPath $verifier -PathType Leaf)) {
        $verifier = Find-Cm400Verifier -RepoRoot $RepoRoot
    }
    if (-not $verifier) {
        Note 'crypto-verification-ran' $false 'cm400-catsig.exe was not supplied and is not built; refusing to fall back on a trust-state enum'
        Fail 42 'the pinned-certificate verifier is unavailable, so the package cannot be accepted'
    } else {
        # the pinned DER comes from this repository when the repository has it; otherwise the shipped
        # certificate is used, which section 1 has already proven byte-identical to the pinned value
        $pinCer = Join-Path $RepoRoot 'install\cm400-release.cer'
        if (-not (Test-Path $pinCer)) { $pinCer = Join-Path $PackageDir 'cm400.cer' }
        $bind = @()
        foreach ($p in @("cm400.inf=$(Join-Path $PackageDir 'cm400.inf')", "SHA256SUMS.txt=$(Join-Path $PackageDir 'SHA256SUMS.txt')")) {
            $fp = $p.Split('=')[1]
            if (Test-Path $fp) { $bind += '--bind'; $bind += $p }
        }
        $cryptoOut = & $verifier verify --cat $catPath --cer $pinCer @bind 2>&1 | Out-String
        $cryptoExit = $LASTEXITCODE
        ($cryptoOut -split "`r?`n" | ?{ $_.Trim() }) | %{ Write-Host ('    catsig| ' + $_.Trim()) }
        $sigLegOk = ($cryptoExit -eq 0) -and ($cryptoOut -match 'VERDICT ACCEPTED') -and
            ($cryptoOut -match '(?m)^OK   signature') -and ($cryptoOut -match '(?m)^OK   embedded-identity')
        Note 'crypto-verification-ran' $sigLegOk "exit=$cryptoExit verifier=$(Split-Path -Leaf $verifier) pin=$(Split-Path -Leaf $pinCer)"
        if (-not $sigLegOk) { Fail 40 'cryptographic verification against the pinned certificate did not accept this package' }

        # differential: the same signature must be refused when a key that is not ours is named. Without
        # this, a leg that quietly stopped checking anything would still report success.
        $foreign = $null
        foreach ($c in @(Get-ChildItem Cert:\LocalMachine\Root -EA SilentlyContinue)) {
            if ($c.Thumbprint -ne $wantThumb) { $foreign = $c; break }
        }
        if (-not $foreign) {
            Note 'wrong-key-differential' $false 'no foreign certificate was available to test with'
            Fail 42 'the wrong-key differential could not be run, so verification is unproven'
        } else {
            $fder = Join-Path $env:TEMP "cm400-foreign-$([guid]::NewGuid().ToString('N').Substring(0,8)).cer"
            [IO.File]::WriteAllBytes($fder, $foreign.RawData)
            $negOut = & $verifier negative --cat $catPath --der $fder 2>&1 | Out-String
            $negExit = $LASTEXITCODE
            Remove-Item $fder -Force -EA SilentlyContinue
            # Exit code 0 alone is not the evidence. The verifier uses 0 to mean "the foreign key was
            # refused at the signature check itself", 4 for "the foreign key was accepted" (the dangerous
            # outcome), 5 for "never reached the signature check" (which proves nothing) and other codes
            # for "no verdict". So the refusal has to be read, and it has to name the verification
            # control and a hexadecimal error, which is what separates a real signature rejection from a
            # run that could not parse the message. The positive leg already proved this message opens
            # and verifies under our key, so a refusal here cannot be vacuous while that leg passed.
            $refused = ($negExit -eq 0) -and ($negOut -match 'negative-control=REFUSED') -and
                ($negOut -match 'VERIFY_SIGNATURE_EX.*(0x[0-9A-Fa-f]{8}|CRYPT_[A-Z_]+)')
            Note 'wrong-key-differential' $refused "foreign=$($foreign.Thumbprint.Substring(0,8)) exit=$negExit refusal-observed=$refused $(if ($negOut -match 'as required: (.+)') { $Matches[1].Trim() })"
            if (-not $refused) {
                Write-Host ($negOut -replace '(?m)^', '    neg| ')
                Fail 41 'a signature verified against a foreign key was accepted: the crypto leg is not actually checking'
            }
        }
    }
}

# ---- 3. the INF and the digest list must be members of that signed catalog --------------------
$err = ''
$members = @()
$toolOk = $true
try { $members = [Cm400CatInterop]::MemberIds($catPath, [ref]$err) }
catch { $toolOk = $false; $err = $_.Exception.Message }
if (-not $toolOk) {
    Note 'catalog-members-readable' $false "the OS catalog API could not answer: $err"
    Fail 16 'catalog membership could not be established independently (this is a tooling failure, not a pass)'
} else {
    # keep the two CRYPTCAT_MEMBER fields apart. CryptCATEnumerateMember hands back a reference tag (the
    # digest the catalog indexes the file by) and, optionally, a file name; collapsing them into one
    # string with a fuzzy match would let a member that merely names the right file pass without
    # attesting to its content, which is not the claim this check is supposed to support.
    $records = @($members | ForEach-Object {
        $parts = "$_" -split "`t", 2
        [pscustomobject]@{ Tag = $parts[0]; File = $(if ($parts.Count -gt 1) { $parts[1] } else { '' }) }
    })
    Note 'catalog-members-readable' ($records.Count -gt 0) "members=[$(($records | ForEach-Object { $_.Tag + '|' + $_.File }) -join ' ')]"
    foreach ($name in @('cm400.inf', 'SHA256SUMS.txt')) {
        $path = Join-Path $PackageDir $name
        if (-not (Test-Path $path)) { Fail 14 "$name is missing"; continue }
        $sha1 = (Get-FileHash $path -Algorithm SHA1).Hash.ToUpperInvariant()
        $verdicts = @($records | ForEach-Object { Test-CatalogMember -Member $_ -ExpectedTag $sha1 -ExpectedFile $name })
        $match = @($verdicts | Where-Object { $_.matched })
        Note "member-of-signed-catalog:$name" ($match.Count -eq 1) "digest $sha1; $((@($match)[0]).why)$(if ($match.Count -gt 1) { " ; $($match.Count) members claim this file" })"
        if ($match.Count -eq 0) {
            Fail 13 "$name is not attested by any catalog member whose reference tag matches its digest"
        } elseif ($match.Count -gt 1) {
            Fail 13 "more than one catalog member claims to attest $name"
        }
    }
    # the signing flow produces exactly these two members; a third would mean this catalog came from a
    # different package assembly than the one documented, and silence about that is how drift hides
    Note 'catalog-member-set-is-the-documented-two' ($records.Count -eq 2) "count=$($records.Count)"
    if ($records.Count -ne 2) { Fail 13 "the catalog holds $($records.Count) members where the documented package has two" }
}

# ---- 4. exact whitelist, then digests against the catalog-attested list ----------------------
$expected = @(
    'LICENSE', 'SHA256SUMS.txt', 'cm400.cat', 'cm400.cat.thumbprint.txt', 'cm400.cer',
    'cm400-setup.exe', 'cm400.inf', 'cm400ctl.exe', 'cm400d.exe'
)
$actual = @(Get-ChildItem $PackageDir -File | ForEach-Object { $_.Name })
# not `-File` at the top level only: a subdirectory (or a hidden or reparse entry) would make the
# nine-file check blind to whatever it contains, and "the package is flat" is part of the format
$layoutProblems = @(Get-PackageLayoutProblems -Dir $PackageDir -ExpectedFiles $expected)
Note 'file-set-is-exactly-the-whitelist' ($layoutProblems.Count -eq 0) "top-level files=$($actual.Count) problems=[$($layoutProblems -join ' ; ')]"
if ($layoutProblems.Count) { Fail 14 'the package directory is not exactly the nine whitelisted files' }

$listed = @{}
foreach ($line in @(Get-Content (Join-Path $PackageDir 'SHA256SUMS.txt') -EA SilentlyContinue)) {
    if ($line -match '^([0-9a-fA-F]{64})\s+\*?(.+)$') { $listed[$Matches[2].Trim()] = $Matches[1].ToUpperInvariant() }
}
# the list attests the shipped material; it cannot attest to itself, and cm400.cat is what signs it
$mustCover = @($expected | Where-Object { $_ -notin @('SHA256SUMS.txt', 'cm400.cat') })
$uncovered = @($mustCover | Where-Object { -not $listed.ContainsKey($_) })
Note 'digest-list-covers-release-files' ($uncovered.Count -eq 0) "entries=$($listed.Count) uncovered=[$($uncovered -join ',')]"
if ($uncovered.Count) { Fail 15 "the digest list does not cover: $($uncovered -join ', ')" }
$digOk = $true
foreach ($name in $listed.Keys) {
    $p = Join-Path $PackageDir $name
    if (-not (Test-Path $p)) { Fail 15 "the digest list names $name which is not in the package"; $digOk = $false; continue }
    $h = (Get-FileHash $p -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($h -ne $listed[$name]) { Fail 15 "$name digest mismatch: list says $($listed[$name].Substring(0,16)) disk says $h"; $digOk = $false }
}
Note 'digests-match-disk' $digOk 'each listed file hashed from disk and compared with the catalog-attested list'

if ($script:exitCode -ne 0) {
    Write-Host "::error::candidate pre-verification failed (code $script:exitCode); no file from the package was executed"
    exit $script:exitCode
}
Write-Host '  pre-execution verification passed: pinned identity, signed catalog attests the digest list, exact file set, digests match'
exit 0
