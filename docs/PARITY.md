# Tessera Cross-Language Parity — Evidence

> **Status:** Self-reviewed by the Ciphera team; NOT independently audited.

Tessera's central technical risk is **silent cross-language divergence**: the Go server SDK, the
TypeScript/WASM browser SDK, and the Rust core/sidecar must agree byte-for-byte, or a user who registers
in the browser cannot be authenticated by the server. This document records how that parity is *proven*,
not assumed — mechanically, in CI, on every commit, across architectures.

There are three independent parity surfaces, each proven by a live cross-language test, plus a
conformance kit any future implementation can self-check against.

---

## 1. The three live parity surfaces

### 1a. OPAQUE wire — WASM ↔ native sidecar (handshake gate)
The browser SDK's WASM OPAQUE client and the native Rust sidecar are compiled from the **same**
`opaque-ke` core (`TesseraCipherSuite`), so wire interop holds **by construction**, not by two libraries
agreeing. The `handshake-gate` CI job proves it empirically: a full register→login round-trip over the
framed IPC channel, asserting the client (WASM) and server (sidecar) derive the **same** `session_key`
and a **stable** 64-byte `export_key` across two independent logins. Because GitHub runners are x86-64
and local dev is aarch64, the gate passing in CI proves **wasm32 ↔ x86-64 OPAQUE/Argon2 byte-determinism**
on the production sidecar architecture.

### 1b. Vault envelope — TS ↔ Go (Open-parity)
Vault encryption is non-deterministic (random nonces), so byte-exact envelope equality is impossible;
parity is the **Open** direction. The `vault-parity` harness seals in one language and opens in the other
(both directions), recovering the exact plaintext, and a wrong context fails (key separation). This
proves the HKDF 32-zero salt, the `AAD = version‖context`, and the envelope layout match across Go's
stdlib and the browser's WebCrypto.

### 1c. Blind index — TS ↔ Go (byte-exact)
Argon2id over a fixed salt is deterministic, so the blind index is **byte-exact** cross-language. The
`blindindex-parity` harness asserts the TS/WASM `blindIndexString` equals the Go `BlindIndexString`
character-for-character, including normalization-boundary and Unicode inputs — proving Rust `argon2` ==
Go `x/crypto/argon2` and Rust `str::to_lowercase` == Go `strings.ToLower` on the pinned inputs.

---

## 2. The conformance kit (third-party self-certification)

Beyond the live Go↔TS gates, the canonical kit in [`../conformance/`](../conformance/) lets **any** future
implementation (Rust/Python/Swift/…) self-certify with no contact with us. See
[`../conformance/CONFORMANCE.md`](../conformance/CONFORMANCE.md) for the procedure. Coverage:

| File | What it pins |
|------|--------------|
| `blind-index.json` | 11 byte-exact blind indices (incl. whitespace/case/Unicode boundaries) + `normalizedEmail` KAT |
| `vault.json` | 7 Open-parity envelopes (incl. empty→89B, 4 KiB, multibyte UTF-8, identity-context) + `kekHex` KAT |
| `vault-negative.json` | 5 rejection vectors (version / truncation / tamper / wrong-key / wrong-context → error class) |
| `vmk-wrap.json` | 3 browser-only VMK-wrap Open-parity vectors + `wrapKekHex` KAT |

The Go verifier (`tessera-go` `conformance_test.go`, white-box) checks the byte-exact KATs against the
SDK's actual internals; the TS verifier (`tessera-ts` `test/vectors.test.ts`) checks Open-parity and the
negatives, and verifies the KEK/wrap-KEK/normalization KATs **transitively** (those values are
non-extractable WebCrypto keys / run inside the WASM core — see `CONFORMANCE.md`).

---

## 3. CI evidence

All parity surfaces run on every push to `main`, cross-architecture (x86-64 runners):

- **tessera-go** `ci`: `unit` + `integration` (real WASM↔sidecar handshake is the tessera-ts gate; the
  Go integration test drives a real sidecar) + **`conformance`** (the kit). Green: runs `26946944503`
  (P1.0), `26958479120` (P1.1, with KATs + negatives).
- **tessera-ts** `tessera-ts`: `rust` → `handshake-gate` → `ts-tests` (26-test conformance verifier) →
  `browser` (Chromium + WebKit). Green: runs `26946947293` (P1.0), `26958480544` (P1.1).
- **ciphera-tessera (core)** `ci`: `test`. Green: runs `26946925820`, `26958474364`.

---

## 4. Honest coverage limits

- The **real-browser** matrix (`browser` job) exercises the web-target WASM + WebCrypto on Chromium +
  WebKit against a *curated subset* of the conformance vectors hard-coded in `crypto.spec.ts` — not the
  full kit. The full kit is exercised by the Node `ts-tests` job and the Go `conformance` job; the
  browser job proves the browser *glue* (web-target wasm load + the real WebCrypto path), not exhaustive
  vector coverage.
- **WebAuthn-PRF** in the browser matrix **SKIPs** (does not fail): the Chromium CDP virtual authenticator
  in the CI image does not surface the PRF extension. The PRF crypto path is unit-proven (Node, injected
  PRF); promoting it to a real-ceremony PASS needs a physical authenticator or a Chromium build exposing
  PRF via CDP.
- Offline **OPAQUE handshake vectors** are intentionally absent (interop is by-construction + the live
  gate; serializing `opaque-ke` internal state is impractical) — see `CONFORMANCE.md` §Out of scope.
