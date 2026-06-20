# Tessera — Documentation & Audit Package

> **Status:** Self-reviewed by the Ciphera team; not yet independently audited. Tessera is open-source
> zero-knowledge identity software (OPAQUE auth + a client-encrypted vault). It has had a rigorous
> internal self-audit — read the spec and threat model, and review the code, before relying on it.

This package is the auditor-facing (and eventual public) doc set for Tessera v1 (suite `0x01`). It is
designed to be hand-off-ready: an external reviewer (or a community auditor) receives these documents,
the conformance kit, and the source of all three repos, with no re-prep required.

## Contents

| Document | What it covers |
|----------|----------------|
| [`SPEC.md`](./SPEC.md) | Protocol & wire spec: OPAQUE suite/KSF, blind index, vault & VMK-wrap envelopes, sidecar wire protocol, error taxonomy, encodings |
| [`THREAT-MODEL.md`](./THREAT-MODEL.md) | In-scope/out-of-scope adversaries, guarantees, and the honest residual limits |
| [`SELF-AUDIT.md`](./SELF-AUDIT.md) | The internal self-audit: scope, methodology, all 13 findings + remediation status, claims upheld |
| [`PARITY.md`](./PARITY.md) | Cross-language parity evidence: the three live gates + the conformance kit + CI |
| [`DEPENDENCIES.md`](./DEPENDENCIES.md) | Security-relevant dependency inventory + supply-chain posture |
| [`AUDIT-SCOPE.md`](./AUDIT-SCOPE.md) | Target of evaluation, by-construction vs needs-eyes, non-goals (for a future reviewer) |
| [`SECURITY.md`](./SECURITY.md) | Responsible-disclosure policy |
| [`../conformance/`](../conformance/) | The conformance kit: vectors + `CONFORMANCE.md` (procedure) + `schema.md` (pinned constants) |

## The repos

- `ciphera-net/tessera` (this repo) — Rust OPAQUE core + `tessera-sidecar` + the conformance kit + these docs.
- `ciphera-net/tessera-go` — Go server SDK.
- `ciphera-net/tessera-ts` (`@ciphera-net/tessera`) — browser SDK (WASM OPAQUE + WebCrypto vault).

## Assurance

The only review to date is the internal self-audit ([`SELF-AUDIT.md`](./SELF-AUDIT.md)): 0 critical, 0
high; cryptographic-correctness clean; the findings were hygiene / supply-chain / documentation-accuracy
issues, 8 remediated and 5 accepted as documented residuals. This is **not** a substitute for an
independent third-party audit, and every document in this package says so.
