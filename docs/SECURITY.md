# Security Policy

> **Status:** Self-reviewed by the Ciphera team; not yet independently audited. This is open-source
> cryptographic software — review the code and the threat model ([`THREAT-MODEL.md`](./THREAT-MODEL.md))
> before relying on it.

## Reporting a vulnerability

Report security issues **privately** to **security@ciphera.net**. Please do **not** open a public issue
for a suspected vulnerability.

Include, where possible: affected component (`ciphera-tessera` core/sidecar, `tessera-go`, or
`@ciphera-net/tessera`) and version/commit, a description and impact assessment, and a minimal
reproduction. PGP-encrypted reports are welcome; the key fingerprint is published alongside the
`security@` address.

## Our commitment

- **Acknowledgement** within 3 business days.
- **Triage + initial assessment** within 10 business days, with a severity and a remediation plan.
- **Coordinated disclosure:** we request a **90-day** embargo from first report to public disclosure, or
  until a fix ships — whichever is sooner — and will coordinate timing with you.
- **Credit:** we credit reporters in the advisory unless you prefer to remain anonymous.

## Safe harbour

We will not pursue or support legal action against good-faith security research that: respects the
embargo; avoids privacy violations, data destruction, and service degradation; only interacts with
accounts/data you own or have explicit permission to test; and gives us a reasonable window to remediate
before disclosure. Good-faith research conducted under this policy is authorised.

## Supported versions

Until the first stable release, only the latest `main` of each repository is supported. After a stable
release, the most recent minor series receives security fixes.

## Scope

**In scope:** the cryptographic core and protocol (`ciphera-tessera`), the Go server SDK (`tessera-go`),
the browser SDK (`@ciphera-net/tessera`), and the pinned wire/crypto contract (see [`SPEC.md`](./SPEC.md)).

**Out of scope / known limits:** the residual limits documented in [`THREAT-MODEL.md`](./THREAT-MODEL.md)
are known and accepted for v1 (e.g. non-extractable keys are an API-layer guard, not process isolation;
constant-time execution is not fully achievable in TS/WASM; the recovery phrase is an immutable,
un-zeroable string). Reporting one of these documented limits is welcome but will be triaged as a known
limitation rather than a new vulnerability.
