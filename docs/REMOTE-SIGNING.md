# Remote signing for a fixed self-signed identity

Status: **design only. Nothing here is deployed, and no signing happens on GitHub today.**

The release uses one fixed **self-signed** publishing identity for both the inner catalog and the outer
executable, so that upgrades, trust maintenance and uninstall cleanup can keep matching the same
certificate. A GitHub-hosted runner must never hold that private key or its password, and the key is never
placed in GitHub Secrets. That rules out running the current local signing steps inside a workflow, and it
rules out any service that would sign with a *different* certificate: replacing the identity would break
the pinned comparison the installer relies on, and weakening that comparison is not an option either.

So the design separates two things that the local flow currently does in one place: **building** the
artifact (which GitHub does, and does publicly) and **signing** it (which an endpoint outside GitHub does,
under a policy that only this workflow can ask for).

## Roles

| Component | Runs where | Holds the private key | May publish |
| --- | --- | --- | --- |
| Build job | GitHub-hosted runner (Windows) | no | no |
| Signing endpoint | infrastructure owned by the maintainer, outside GitHub | yes, never leaves | no |
| Verification and release job | GitHub-hosted runner | no | yes, Draft Release only |

## Authorisation: GitHub OIDC, not a stored credential

The endpoint accepts a request only when it can verify a GitHub OIDC token against GitHub's issuer, and the
token's claims match a fixed allow-list:

- `repository` equals the exact `owner/repo`;
- `repository_owner` equals the expected account;
- `job_workflow_ref` equals the exact `owner/repo/.github/workflows/<file>.yml@<pinned ref>` — not a
  floating branch, and the comparison is made against a configured value, not against anything the request
  body asserts;
- `ref` is the tag or protected-environment ref the release policy names;
- `run_id` and `run_attempt` are recorded for audit, and the token's lifetime bounds the request.

The endpoint never accepts a shared static secret as the primary authorisation, because a static secret is
exactly the thing that can leak from a runner. A short-lived OIDC token is presented per request.

## What the endpoint is allowed to do

Two operations, no more:

1. `sign-catalog`: accept the unsigned `.cat` produced by `makecat`, sign it with the fixed identity, add an
   RFC 3161 timestamp, return the signed catalog and its digest;
2. `sign-executable`: accept the assembled single-file installer, sign it with the fixed identity, add an
   RFC 3161 timestamp, return the signed executable and its digest.

It refuses everything else. In particular:

- **no arbitrary file signing**: the input must satisfy a structural pre-check before it is signed - for the
  catalog, that it parses as a PKCS#7 SignedData whose member set is exactly the documented two members; for
  the executable, that its PE header is well-formed and its imported certificate slot is the only region
  the operation will modify. A request to sign a file that is not a candidate artifact of this build is
  refused even with a valid OIDC token.
- **no replay**: each request carries the build's subject digest (SHA-256 of the exact bytes sent) plus the
  OIDC `jti`/`run_id`; the endpoint records digests it has already signed and rejects a second signature over
  different bytes presented as the same build, and it rate-limits per claim set.
- **no key export in any form**: the key never leaves its storage; the endpoint returns only signed outputs.

## Order of operations, and why it is this order

```
build binaries and tests
  -> inner manifest (SHA256SUMS.txt) and catalog (.cat) generated for the final layout
  -> catalog signed + timestamped                 (endpoint operation 1)
  -> bundle assembled into the installer, index written
  -> layout and inner verification run on the assembled, UNSIGNED file
  -> outer executable signed + timestamped        (endpoint operation 2)
  -> signature verification on the SIGNED file
  -> provenance attestation bound to the signed bytes
  -> Draft Release created and that exact file uploaded
  -> server-side digest read back, file downloaded again and re-hashed
```

Signing is last and nothing is modified afterwards, so the digest that is attested, released and verified is
the digest of the bytes that were signed. The bundle's trailer is located by its own magic and the
certificate table's real offset: signing appends an attribute table after the bundle and aligns it, so
"end of file minus a constant" would miss the payload on a signed artifact.

## Audit record

For every signing request the endpoint keeps, and the workflow prints the same fields:

- OIDC claims used for authorisation (`repository`, `job_workflow_ref`, `ref`, `run_id`);
- source commit SHA the build job reported, and the workflow run URL;
- SHA-256 of the bytes received and of the bytes returned;
- signer certificate thumbprint and its DER SHA-256, compared against the pinned identity;
- timestamp authority response and the token's validity window;
- the operation performed (`sign-catalog` | `sign-executable`), and the policy decision with its reason.

Key material, passwords and the signing host's credentials are never part of this record.

## Fail-closed behaviour

Every one of these ends the release with a non-zero status and no published artifact: an unverifiable or
mismatched OIDC token; a request whose structure check fails; a returned file whose digest is not the digest
of what was sent; a signer thumbprint or DER hash that is not the pinned identity; a missing or
unparsable timestamp; a failure of the post-sign verification below; any mismatch between the released
asset's server-side digest and the digest of a freshly downloaded copy.

## Re-running the existing gates on the returned file

The signed artifact is not trusted because it came back signed; it is checked by the same gates that guard
local builds, all of which take the shipped single file as input:

- `cm400-catsig verify` against the pinned public certificate, with `cm400.inf` and `SHA256SUMS.txt` bound to
  the files that came out of this bundle;
- `cm400-bundle list` / `extract` on the signed host, and per-member digests recomputed from disk;
- `cm400-setup verify-package --staged` on the expanded payload;
- the single-file gates, including the negatives: a flipped payload byte refused by the container, a host-code
  flip that the inner chain cannot see (so the outer signature and published digest are what catch it), an
  index-consistent but manifest-inconsistent payload refused by name of the disagreeing digest, a look-alike
  directory that is not this host's payload refused, and an extra bundle member refused by the whitelist;
- the release asset guard: exactly one file, nothing internal inside it.

## What is missing before this can run

1. An endpoint. There is none today: no signing service is deployed, and nothing here has been exercised
   end to end. Building it needs a host outside GitHub that holds the identity, a policy for who may ask it,
   and a way to store its audit records.
2. A key-custody decision. The fixed identity's private key must be resident on that host in some form.
   Options with different trade-offs, none chosen here: an HSM-backed key where the certificate can be
   imported and still matches the existing thumbprint; a software keystore on a hardened, network-restricted
   host; or a commercial remote-signing service - which has to be shown to sign *with this certificate*,
   because services that substitute their own certificate would change the pinned identity and are refused.
3. A test path that does not touch production: the endpoint must be exercised against a throwaway identity
   first, then against the real one only when the design above is accepted, and no unsigned or
   differently-signed artifact may be published in the meantime.
4. The workflow itself. `github-build-probe.yml` measures whether GitHub can build and attest provenance on
   this repository; a release workflow that signs remotely is a separate piece of work and is not part of
   that measurement.

## Boundary this document does not cross

Publishing the source, or attesting a build, says where a binary came from. It does not say the software is
safe, it does not mean Windows trusts the publisher - the identity is self-signed and a fresh machine will
not trust it until the installer enrolls it after the user verifies the published digest and approves
elevation - and it does not remove unknown-publisher or SmartScreen warnings.
