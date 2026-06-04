# Tessera — Audit Scope & Non-Goals

> **Status:** Self-reviewed by the Ciphera team; NOT independently audited. This document scopes the
> system for a *future* external reviewer; today the only review performed is our internal self-audit
> ([`SELF-AUDIT.md`](./SELF-AUDIT.md)).

This document defines the **target of evaluation (TOE)**, what is proven *by construction* versus what
needs human eyes, the suggested focus areas, and the explicit non-goals — so the package is hand-off-ready
the moment funds or a volunteer reviewer appear, with zero re-prep.

---

## 1. Target of evaluation

| Repo | Role | Language |
|------|------|----------|
| `ciphera-net/tessera` (`ciphera-tessera`) | OPAQUE core + `tessera-sidecar` + the conformance kit + these docs | Rust |
| `ciphera-net/tessera-go` | Go server SDK (sidecar client, blind index, vault) | Go |
| `ciphera-net/tessera-ts` (`@ciphera-net/tessera`) | Browser SDK (WASM OPAQUE, vault, VMK, recovery, passkey) | TS + Rust/WASM |

The pinned cryptographic contract is specified in [`SPEC.md`](./SPEC.md) and machine-checked by
[`../conformance/`](../conformance/). The TOE is the integration/protocol layer Tessera *authors* — not
the underlying primitives (see §4).

---

## 2. Proven by construction (lower review priority)

- **OPAQUE wire interoperability:** the browser and the sidecar compile the **same** `opaque-ke` core, so
  they cannot disagree on the wire — verified by the live handshake gate ([`PARITY.md`](./PARITY.md) §1a).
- **Cross-language parity:** blind index (byte-exact), vault (Open-parity), VMK-wrap (Open-parity) are
  pinned by the conformance kit and re-verified in both SDKs' CI on every commit ([`PARITY.md`](./PARITY.md)).

## 3. Suggested focus areas (where exploitability lives)

Scoped from the threat model ([`THREAT-MODEL.md`](./THREAT-MODEL.md)) — the same dimensions our self-audit
covered, offered as a starting map, not a limit:

1. **Zero-knowledge boundary** — does `export_key` / raw VMK / password file ever reach the client or a log?
2. **Cryptographic construction** — KEK/DEK/HKDF/AAD usage, nonce management, key separation, splice resistance (the primitives are upstream; the *composition* is ours).
3. **Secret hygiene** — zeroization coverage and the honest limits (GC, WASM linear memory, immutable recovery-phrase string).
4. **Oracle resistance & constant-time posture** — the single-error-class Open path; the timing-safe unknown-account path; per-language CT limits.
5. **Process/memory boundary** — non-extractable key discipline and its honest limit (API-layer guard, not process isolation).
6. **Supply chain** — see [`DEPENDENCIES.md`](./DEPENDENCIES.md).

---

## 4. Non-goals / out of scope

- **Underlying primitives are NOT re-audited here.** Tessera composes vetted, externally-audited
  primitives — `opaque-ke` (NCC), Go stdlib `crypto/*` (Trail of Bits), WebCrypto, `@noble/*`,
  `curve25519-dalek`, `argon2`. The review target is Tessera's *integration* of them, not the primitives.
- **No new cryptographic primitives** exist in Tessera to review (by design).
- **Post-quantum algorithms** are out of v1 (only PQ-*readiness*: versioned envelopes + a KEM/KDF seam).
- **The relay/envoy E2E path** is a v2 expansion, not present in v1.
- **Production dogfooding / the SRP→OPAQUE migration** is a separate phase, not part of this TOE.
- **Offline OPAQUE handshake vectors** are intentionally absent (interop is by-construction + the live
  gate) — see [`../conformance/CONFORMANCE.md`](../conformance/CONFORMANCE.md).

---

## 5. Assurance status

The only review to date is the internal self-audit in [`SELF-AUDIT.md`](./SELF-AUDIT.md). It is **not** a
substitute for an independent third-party audit; every artifact in this package says so. An external
auditor receives: this scope, [`SPEC.md`](./SPEC.md), [`THREAT-MODEL.md`](./THREAT-MODEL.md),
[`PARITY.md`](./PARITY.md), [`DEPENDENCIES.md`](./DEPENDENCIES.md), the conformance kit, the full source
of all three repos, and the self-audit report.
