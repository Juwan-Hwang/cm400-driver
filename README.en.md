# CM400 Driver

> **Language note**: this file (`README.en.md`) is the English version; `README.md` is the default Chinese
> version of the same document. Both describe the same commands, the same file names and the same security
> boundaries, and a divergence between them counts as a defect.

System-level, invisible, device-specific driver for the CM400 motorized privacy
webcam (VID `0603` / PID `8612`). When the camera actually starts streaming, the
lens mechanically rises out of the chassis; when streaming stops, it retracts.

It is **not** a control app. There is no window, no tray icon, nothing to launch.
After installation it runs as a background service and the user never touches it.

- Does **not** capture, decode, inspect, store or relay any video frame.
- Does **not** implement UVC. Streaming stays entirely on the OS-native class
  driver (`usbvideo` / `uvcvideo` / Apple UVC).
- Only the mechanical channel is driven, through a strict command whitelist.

## Status

| Platform | State |
|---|---|
| Windows | Implemented and hardware-verified on one machine: motor, activity detection, automatic policy, persistence, Windows service (auto-start, least privilege), install/uninstall/reinstall lifecycle. Scope limits: single capture client (this device does not deliver frames to a second concurrent client), and no genuinely fresh Windows image tested yet - see the maintainer-side release notes (RELEASE-READINESS) |
| Linux | Planned (`uvcvideo` XU ioctl + PipeWire/V4L2 activity + systemd) |
| macOS | Planned (CoreMediaIO activity + DriverKit motor) |

## Getting it (Windows)

A release publishes **one file**: `cm400-setup.exe`. It carries the driver INF, the signed catalog,
the public half of the publishing certificate, the service binary and the licence inside itself, so
there is nothing else to download and no folder to assemble.

Before running it, compare its SHA-256 with the value published alongside the release:

```
Get-FileHash .\cm400-setup.exe -Algorithm SHA256
```

That one number is the out-of-band check on the file you downloaded. It is not a substitute for the
inner verification - and the inner verification is not a substitute for it: the installer re-hashes
every embedded file against the digest list that the signed catalog attests, and refuses before it
changes anything on the machine if any of it disagrees.

- **Double-click with nothing installed**: it explains what it will do, asks for confirmation, then
  requests elevation. On Windows 11 that confirmation is typed (`YES`), and there is no default
  action: Enter does not accept.
- **Double-click with it already installed**: a maintenance menu (status, reinstall, uninstall).
- **From a shell**: `cm400-setup.exe install | uninstall | status | verify-package | harden-acl`,
  and `--license` prints the full Apache-2.0 text. `uninstall` with no terminal attached exits with a
  refusal (exit 28) rather than uninstalling something unasked; diagnostics that need a device are not offered
  by an elevated double-click.
- **What it will not promise**: this is a fixed **self-signed** publishing identity under a custom
  trust model, not a Microsoft-issued certificate. Windows can still show *unknown publisher* or
  SmartScreen for a downloaded file, and the installer neither claims nor attempts to remove those
  warnings. What it does instead is add the one release certificate to the local stores the trust
  decision needs - after you verified the hash and approved UAC - confirm by reading the stores back,
  and remove on uninstall only what it installed itself.

### How build provenance is verified (current state, not dressed up)

The goal is that the published artifact is **built by GitHub Actions from a given commit**, and that whoever
downloads it can verify that build provenance independently. Where this stands:

- This repository is now **public**, and the probe workflow (`github-build-probe.yml`: manual dispatch only, no
  release permissions, every action reference pinned to a full commit SHA) has been run once under each
  visibility. While private, run `38886755727` built successfully but **failed to persist the attestation**,
  with GitHub's own words: `Feature not available for user-owned private repositories. To enable this feature,
  please make this repository public.` After the switch, run `38924226969` (commit `573484c`) **generated the
  attestation**, and `gh attestation verify` inside the workflow exited 0. Per the
  [GitHub Artifact Attestations documentation](https://docs.github.com/en/actions/concepts/security/artifact-attestations),
  attestations for public repositories go to the public Sigstore instance and an immutable transparency log
  that an outside verifier can fetch directly.
- Independent verification was also performed: the artifact was downloaded from that run
  (`cm400-setup.exe`, 790 016 bytes), its SHA-256 recomputed **outside the workflow** as
  `18DE7B44FF80E4572C5D4F85D0063085B81F94681F8FBC44BA0F17E31FAC8B46`, and `gh attestation verify --owner
  Juwan-Hwang` exited 0 with the proof's subject digest equal to that value (in-toto Statement v1).
- Two limits that have to be read together: that proof binds an **unsigned development build**, not a release
  artifact; and Actions artifacts **could not be fetched anonymously** (HTTP 403, login required), so the channel
  an ordinary user can verify has to be the Release asset itself, not a temporary artifact kept during the run.
  The eventual RC4 proof must bind the digest of the **signed** final EXE.
- The final artifact **must be built by GitHub**: a locally built EXE must not be uploaded and described as a
  GitHub build. Signing is unresolved: the fixed self-signed identity's private key must not reach a
  GitHub-hosted runner or GitHub Secrets. Keeping that identity needs a signing service that does not hold the
  key on GitHub (for example an external endpoint authorised by OIDC, restricted to this repository or a
  protected environment). Services such as Azure Artifact Signing use **their own certificates**, which would
  replace the fixed signing identity; they are not adopted without evaluation.
- Until that pipeline exists, the independently checkable facts are exactly two: the source and its commit (pushed
  to the remote and gated by `windows.yml`), and the single SHA-256 published with the release.

How the final artifact can be built by GitHub **without handing the private key to GitHub** is set out in
[`docs/REMOTE-SIGNING.md`](docs/REMOTE-SIGNING.md): the two operations a signing endpoint may perform and
nothing else, how GitHub OIDC restricts it to this repository and a given ref, how replay and arbitrary-file
signing are refused, how it fails closed, and **which infrastructure is still missing**. That document is a
design only - not deployed, not yet exercised end to end - and it does not change the fixed signing identity.

## How it works

- **Activity**: a real-time ETW consumer watches the Microsoft MF-FrameServer
  provider for the per-stream heartbeat (`EventId=10`) and attributes each event to
  *this* device by its USB symbolic link. Activity is therefore "CM400 is really
  streaming", not "some app holds a camera".
- **Motor**: a user-space WinUSB control transfer to the device's motor function
  (MI_02). Open loop - there is no position feedback, so the driver models
  physical state and settles it after the measured maximum travel time.
- **Policy**: asymmetric by design. Rise is eager (privacy exposure is the worst
  outcome); retract is conservative (a grace period absorbs stream restarts).
  Physical state survives restarts and service reinstall/recovery.
- **Device access is on demand**: the motor interface is opened for one command and
  released immediately, so the driver never sits on a DFU-class interface and block
  vendor firmware tools.

## Release model and known limitations (Windows)

> **CM400 Driver never requires a paid signing certificate or a Microsoft-signed
> custom driver.**

- Uses the **Microsoft inbox `WinUSB.sys`**. We do not ship or sign any kernel
  driver of our own; only the driver *package catalog* is signed.
- The CM400 firmware exposes **no Microsoft OS descriptor** (no `0xEE` string, and
  `bcdUSB=2.00` so no BOS / MS OS 2.0). Therefore Windows cannot bind WinUSB
  automatically, and a custom `.inf` package is technically required - "just plug it
  in, zero driver package" is not achievable on this hardware.
- Signing is a **build-time** step. The current flow (the local identity_create tooling once, then
  the local sign_fixed_identity tooling per release) signs the catalog with **one fixed self-signed
  publishing identity** whose private key stays in an encrypted PFX outside the repository; the
  shipped package carries only the public certificate and its fingerprint. Writing to the local trust
  stores is **no longer a build-time job** - the installer does it, and can prove it worked.
- Historical note: the local d3_sign_catalog tooling mints a *per-machine* certificate, destroys its key
  after signing and enrolls that certificate locally. That is what produced the still-present
  `346DF6063A90FA2A877384066E8CA0D391438F07`, which is deliberately kept (uninstall must not delete a
  certificate it did not install by record). It is not the release path.
- What `cm400-setup install` checks, each with its own exit code: elevation (20), INF/CAT/CER present
  (21), the whole-package digest list and that the list is itself inside the signed catalog (30), the
  certificate that actually signed the catalog against the pinned identity (29 unresolvable signer,
  31 identity mismatch), trust establishment and its ownership record (33/35), and the package
  verification after trust exists (34). `verify-package` additionally distinguishes "signature valid,
  identity pinned, only this machine does not trust it" as **39** so a build machine can be reasoned
  about without weakening any gate. Nothing here is decided by parsing human-readable output.
- No paid code-signing certificate, no EV certificate and no Partner Center / WHQL attestation
  submission is used. **Windows kernel test-signing mode (`bcdedit /set testsigning on`) is neither
  required nor used as an installation method** - it was explicitly removed from the process.
- Consequence for a release: this is still a **custom trust model**, not a distributable signature.
  The installer now establishes the trust itself, so a target machine no longer has to be pre-
  trusted - but it must be able to run an elevated installer, and strict enterprise policies
  (**WDAC**, **Smart App Control**, driver-blocking AppLocker rules) **may refuse** a locally signed
  driver package regardless. A genuinely clean Windows image has not been tested (one machine, no
  VM); see the maintainer-side release notes (RELEASE-READINESS).
- Uninstall removes what CM400 owns: the service registration, our driver package from the Driver
  Store, the files under `C:\ProgramData\CM400` (state, log and rotated archives), **the deployed
  service image under `C:\Program Files\CM400`**, the release's own certificate from
  `LocalMachine\Root` and `LocalMachine\TrustedPublisher`, and finally the ownership record itself.
  Which stores may be cleaned is decided by that record, per store: `AddedByInstall` is removed, a
  certificate that was already `Preexisting` is left alone, an absent record falls back to the
  approved legacy path, and a record that cannot be believed **stops automatic cleanup** (exit 37)
  instead of being guessed at. A certificate is deleted only when its DER SHA-256 matches the pinned
  identity, its thumbprint locates exactly one entry, its subject is `CN=CM400 Driver` and it is
  self-signed, and the store is re-read afterwards to confirm the outcome. The deployed image is
  removed only when the image the SCM had registered parses to that exact path (never a substring
  match), the registration is confirmed gone by re-querying, and the tree holds nothing this product
  did not put there; otherwise it is kept and the reason printed. The ownership record is deleted only
  after certificate cleanup is confirmed, so an unverified state keeps the record. It never touches
  another vendor's package or certificate - verified with a third-party root certificate as decoy.

### Release model decision (identity, trust establishment and the lifecycle are verified on this machine; a clean Windows image is not)

The constraint stands: no certificate is purchased. "Installs on a clean machine" and "no purchased
certificate" are not in conflict - what has to change is the signing and installation flow. The target
design is:

- **One fixed self-signed publishing identity**, reused by every version. The private key lives only
  in a controlled signing environment and never in the repository or a release package. The release
  certificate's fingerprint is `954E6103349748270B90C8A8A68652A44946ABF1` (subject `CN=CM400 Driver`,
  self-signed), which is what the installer pins and what uninstall cleanup is allowed to match against. Today's
  build-time behaviour (mint a new certificate per run, destroy the key immediately after signing)
  is what this replaces: it makes upgrades, trust maintenance and uninstall cleanup needlessly hard.
- **The installer establishes the local trust**, after the user has checked the SHA-256 of the **one
  published file** (the executable, which is all there is to download) and approved UAC. The files
  inside it cannot be trusted to that outer number - the installer re-hashes each embedded member
  against the digest list the signed catalog attests, so a swapped INF, certificate or service binary
  is refused before any store, Driver Store, service registration or deployed image is touched. It
  checks the shipped certificate's fingerprint and the package integrity, adds that one certificate to
  the stores the trust decision needs, verifies the trust actually took effect, and only then installs
  the INF/CAT and registers the service.
  That component now exists (`crates/cm400-windows/src/trust.rs`): it refuses to trust a certificate
  whose fingerprint/subject/self-signed identity does not match the pinned release fingerprint, it
  treats a store it cannot read as *unknown* rather than empty, it confirms every write by
  re-enumerating the store, and it rolls back exactly the stores it wrote - never a pre-existing
  entry. It is exercised by a development-only harness (`cm400-trust-test`), which is rejected by the
  release whitelist instead of adding a switch to the shipped installer. Both paths were measured on
  this machine starting from an **untrusted** state (temporary trust was added only to build the
  package and then removed): the success path wrote trust, confirmed it by re-reading both stores,
  saw the production verifier change from `signature+trust=false` to `true`, and removed the
  certificate again with the precise cleanup; the partial-success path (second store made to fail)
  rolled the first store back and left nothing trusted. **It is now wired into `cm400-setup install`
  and measured end to end on this machine**: a real install exited 0 (identity gate, both stores
  written and confirmed, ownership recorded, driver staged and bound, service running from the
  deployed image), a reboot brought the service back by itself, the lift test moved the lens and
  returned it, and a real uninstall exited 0 removing only our certificate with the older identity
  left intact. **A clean Windows machine remains unverified.**
- Uninstall removes only the certificate this product installed, located by fingerprint, and re-reads
  the store to confirm it is gone (implemented and verified on this machine).

Stated plainly, because the label matters: Microsoft documents automatic placement of trusted
publisher certificates as intended for **organization-internal driver testing and debugging**, not for
packages distributed outside an organization. This is therefore a **custom trust model** - the user
verifies the files, then the installer establishes self-signed trust - and not a Microsoft-endorsed
release signature. Nor is it a claim that warnings disappear: until the certificate is trusted, UAC can
still show an **unknown publisher**, a downloaded executable can still trigger **SmartScreen**, and
policy-managed machines may still refuse the package. Hash verification tells a user the files match
the published ones; it promises nothing about those prompts.

Measured on this machine, with the fixed identity created first and left untrusted on purpose
(the local identity_create tooling -> the local sign_fixed_identity tooling -> the local trust_experiment tooling
-Experiment A`): before importing the public certificate, the installer's own verifier reports
`signature+trust: FAIL - WinVerifyTrust failed with 0x800b0109` (untrusted root) while `membership`
still reports `OK` - the two claims are separate; after importing, both are `OK`; after cleanup the
certificate is gone from both stores, the older production certificate is still there, and the service
and device were never touched (`Running`, lens `down` throughout). That is a **local trust-mechanism
verification**, not a clean-Windows first install: this machine still has the Driver Store entry, the
device binding and the registry state, and no experiment run here can stand in for a fresh image.

Status of the three experiments that had to be separated: **A** (a trusted self-signed package is
accepted) passed on this machine; **B** (the installer establishes the trust itself) is implemented,
wired into `cm400-setup install` and passed on a real install; **C** (uninstall / reinstall) has been
run on this machine - a real uninstall exited 0 with certificate cleanup driven by the ownership
record, and a reinstall afterwards also exited 0. This is still one machine holding its own only
working install, so none of it substitutes for a fresh image.

The release status stays **developer / beta** for reasons that are concrete, not procedural, and they are
now split cleanly. What has become a CI fact: `.github/workflows/windows.yml` is green on the release
branch head, and `.github/workflows/release-candidate.yml` completed its full two-job acceptance on the
commit `v0.1.0-rc2` points at - one job reads the draft release (a draft is listable only by a
push-capable identity, which is why the privileged job checks out nothing, builds nothing and executes
nothing it downloads) and hands the release asset over - nine files in the rc2-era shape, and from rc4 a
single self-contained installer that the acceptance job expands before judging it - while the
acceptance job holds no credential at all, rebuilds the catalog verifier from the pinned toolchain,
requires its own checkout to be the commit the
fetch job validated, verifies the catalog against the pinned public key, refuses a foreign key at
`VERIFY_SIGNATURE_EX`, runs the tamper self-test and the attack regression against the downloaded
candidate, and reports the machine unchanged afterwards. The local gates those workflows encode are green
here too: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
`cargo test --workspace --locked`, `cargo check --workspace --all-targets --locked` and
`git diff --check`. Counts are left to the runs themselves rather than restated here, because a hard-coded
total is exactly the kind of claim that goes stale.

What is still **not** proven, and is not written as if it were: no genuinely clean Windows environment has
been tested - the acceptance runner has no device, so it attests the artefacts and the verification chain,
not first-install behaviour on hardware - and the candidate daemon bytes have not yet been observed moving
the lens. Measured on 2026-10-14, the image this development machine actually runs hashes to
`4808E682B9E47167B2813E088FFFD3DB9AE26F90EA26B4E54D61DB0D9F7DC06E` while the candidate ships
`BEABA317495C51C0EAC9C4C734316A45E452D1DA85439410C48CC5EBE6FC7FCD`, so the hardware evidence below belongs
to an earlier build and is not inherited by the candidate bytes until an upgrade installs them and the
behaviour is observed again.

What was open on 2026-10-13 morning is now measured - on that pre-candidate deployed image, which is the
correct scope for the claim: the fast-retract path was re-verified with a **real
camera capture on the deployed image that contains the fix** - the stop was attributed on a trusted
ledger, the grace waiver fired, `SET(2)` followed the SAM stop report **303 ms** later (the heartbeat
fallback needs 7-8 s), `LedgerUntrusted` appeared zero times, and the lens reached `physical: Down` with a
confirmation stamped 6.51 s after the command, with exactly two motor commands in the whole round. The two
uninstall cleanups also fired in a real uninstall: `deployed image : ... removed, absence verified` and
`ownership record : removed after confirmed cleanup, absence verified`, with the stores differing from
their pre-uninstall baseline by exactly the pinned certificate. Evidence: the maintainer-side release notes (RELEASE-READINESS) §8d.
Tooling: the local verify_boot_recovery tooling, the local state_audit tooling and
the local capture_uninstall_baseline tooling (all read-only; the last one refuses to record a partial
baseline when unelevated), plus the local trust_transaction_selftest tooling for the temporary-trust
cleanup paths.
A rollback that uninstalls the product is never used as a rollback here: that would remove the driver
package, the service and the persisted state of the machine being protected.

`Zadig` is **not** a product dependency. It is used only as a recovery/experiment tool during
development; the shipping installer performs catalog verification, driver package staging and
binding, service registration, and the local trust enrollment itself (the certificate and its
signature are produced at build time by the fixed-identity signing script, see above).

## Privacy semantics (intentional)

The lens follows **actual video flow**. If an application stops streaming frames -
including the case where the app is still open but backgrounded or video is paused -
the lens retracts after the grace period. For a physical privacy device we prefer
"retracted while nothing is being captured" over "exposed because a window is still
open".

## Building

```
cargo build --workspace
cargo test  --workspace
```

Binaries (in `crates/cm400-windows`):

- `cm400d --console` - foreground host, for development.
- `cm400d --service` - Windows service host (SCM), the shipped form.
- `cm400ctl` - diagnostics (`status`, `raise`, `retract`, `activity-watch`, `usbprobe`). It is built for
  development; its read-only `status` reporting now lives inside the shipped installer as `cm400-setup
  status` (same code path, minus the probes that need a device), and it is not a published asset.
- `cm400-setup` - product entry point for install / uninstall / ACL repair
  (`install`, `uninstall`, `harden-acl`, `verify-package`, plus internal staging steps).
- `cm400-etwprobe`, `cm400-capture-probe`, `cm400-iks-probe` - **development diagnostics, not part
  of a release package**; the last one exists only because the `IKsControl` path was investigated
  and is kept as evidence for a possible future study.
- `cm400-catsig`, `cm400-bundle` - build-time tooling (independent catalog-signature verification; packing
  and listing the bundle). **Never release assets**: the release guard refuses them inside the bundle and
  beside it.

`cm400-setup install` does the whole job on the target machine: verifies elevation, catalog
signature and INF membership with native APIs, quiesces the daemon, stages and binds the device
node, then registers (`sc create`), configures failure recovery, grants the service account its
directory rights and starts the service. It refuses to report success on an unverified interface.
When the installer carries a bundle - which is how a release is built - it unpacks it into a
directory only SYSTEM and Administrators can write, verifies every member before writing anything
anywhere, and removes that directory again when it fails.

The published file is produced by `install/single_file_package.ps1` (build the binaries, write the
inner manifest and catalog, verify the layout, sign last, then re-open the signed executable and
verify again) and policed by `install/release_single_file.ps1`, which refuses a release folder holding
anything except `cm400-setup.exe` and refuses a bundle carrying anything except the release members -
no verifier tool, no probe, no symbols, no second copy of the installer.

What is verified: the full install / uninstall / reinstall lifecycle, and an install with no other
driver package present, both on real hardware. What is **not** verified: a genuinely fresh Windows
image with no prior CM400 driver or interface registration.

For the exact claim-by-claim evidence status of every capability, and the release artifact
whitelist, see **the maintainer-side release notes (RELEASE-READINESS)**.

## Repository protections and how to contribute

`main` is covered by a branch ruleset named `protect-main` (its parameters were read back through the
GitHub API rather than assumed):

- changes must arrive through a pull request, and merging requires the `quality-and-packaging` check from
  `windows.yml` to have passed with the branch up to date;
- the required number of approving reviews is **0**, so a single maintainer is never locked out, and **no
  bypass actors are configured**;
- force pushes (non-fast-forward updates) and deletion of `main` are blocked;
- the repository now requires third-party Actions to be pinned to a full commit SHA, which is why every
  `uses:` line in the three workflows carries a 40-character SHA rather than a branch name or version tag.

## License

Apache-2.0.

## Current status - Windows installation path

> Status update: the Windows device-interface blocker is resolved. `install/cm400.inf` carried a
> malformed interface GUID string (`8-4-4-4-4-4-4` instead of the registry form `8-4-4-4-12`), which
> SetupAPI wrote into `Device Parameters` without complaint while WinUSB could not parse it - so no
> device interface was ever created. With the canonical form, our own GUID now enumerates the motor
> interface on real hardware and the transport opens. Installing with no libwdi driver package present is now
> verified on real hardware; what remains unverified is a genuinely fresh Windows image with no prior CM400
> driver or interface registration.

| Item | Status |
| --- | --- |
| D5 installer failure path + recovery | verified on real hardware |
| D6 uninstall end to end | verified - judged by post-uninstall machine state, not by the exit code: service gone (1060), our package removed, CM400 files removed, while the libwdi package, MI_02's binding, MI_00 (usbvideo) and the motor path all stay untouched |
| Native trust verification (WinVerifyTrust / CryptCAT) | verified - a valid package, a tampered catalog, a tampered INF and a valid-but-untrusted signer each give a distinct outcome, and the installer needs no SDK tool at runtime |
| Our own device interface is created automatically | verified - `interface FOUND via production INF`, path `...#{11a9c0d3-5f2b-4e7a-9c31-0b6d2e4f8a10}`, motor transport reachable; pinned by a contract test that compares `install/cm400.inf` against the Rust binary GUID |
| Automatic raise/retract driven by activity, on our own interface | verified - open CM400 stream: exactly one `SET(1)` carrying `[via production INF ...#{11a9c0d3-...}]`; stop stream: `Active -> Inactive` after 3.0s and exactly one `SET(2)` 10.1s later, still on our interface |
| Built-in-camera negative test, on our own interface | verified - ~40s of the built-in camera produced zero CM400 heartbeats (`cm400_heartbeats` 189 -> 189) and zero motor commands |
| Physical raise/retract through our own interface | verified on real hardware - one `SET_CUR` each way through the production interface (no fallback to the Zadig GUID): raise confirmed `physical: Up` after 6.4s, retract confirmed `physical: Down` after 6.4s, with the operator visually confirming both movements |
| Install / uninstall / reinstall lifecycle, on our own driver | verified by post-action machine state (not exit codes): uninstall removed the service, our package and CM400's files while leaving the libwdi package and MI_00's usbvideo binding untouched; reinstall bound our package, produced the canonical GUID in `Device Parameters`, enumerated our own interface, opened the transport and left the service RUNNING |
| Install with no libwdi driver package present | verified - both driver packages were removed from the Driver Store, the device re-arrived with no driver at all, and `cm400-setup install` alone bound our INF, produced the canonical GUID in `Device Parameters`, enumerated our own interface, opened the transport and started the service (`INSTALL COMPLETE`, exit 0) |
| Physical raise/retract after a vacuum install | verified - package identity checked as `original=cm400.inf / provider=CM400 Driver / 0.1.0.10` with zero libwdi packages in the store; one `SET(1)` -> `physical: Up` in 6.41s, operator confirmation, then one `SET(2)` -> `physical: Down` in 6.41s, both carrying the production interface path |
| Complete standalone install on a clean Windows | not yet verified - needs a fresh OS image (no prior CM400 driver or interface registration); the no-libwdi-package case above is verified on this machine |

