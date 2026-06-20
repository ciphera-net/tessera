# Tessera Dependencies & Supply Chain

Tessera composes **vetted, externally-audited primitives** and concentrates its originality in the layer
above them (protocol integration, cross-language parity, misuse-resistant API). It implements **no new
cryptographic primitives**. This document inventories the security-relevant dependencies and states the
supply-chain posture. Versions are as observed in the lockfiles at the Phase-4 HEAD.

---

## 1. Supply-chain posture (from the self-audit, dimension 7)

- **Lockfiles pin everything with checksums:** `Cargo.lock` (v4, SHA-256), `go.sum` (h1 base64-SHA-256),
  `package-lock.json` (v3, SRI integrity).
- **No known-CVE / yanked version in a crypto path** as of the audit date (notably `curve25519-dalek`
  is 4.1.3, past the RUSTSEC-2024-0344 fix).
- **Docker base images pinned by digest** (build + runtime stages).
- **`getrandom` `js` feature is the sole wasm RNG path** → `crypto.getRandomValues` is the only entropy
  source on `wasm32`.
- **Accepted residuals (see [`SELF-AUDIT.md`](./SELF-AUDIT.md)):** SC-01 (pin GitHub Actions to SHAs +
  Dependabot), SC-03 (pin the core git-rev dep at public-repo time), SC-04 (add automated advisory
  scanning). SC-02 (`wasm-pack` install) is **fixed** (version-pinned `cargo install --locked`).

---

## 2. Security-relevant dependency inventory

### Rust — `ciphera-tessera` core + sidecar
| Crate | Version | License | Role | Audit status |
|-------|---------|---------|------|--------------|
| `opaque-ke` | 4.0.1 | Apache-2.0/MIT | OPAQUE (RFC 9807) protocol | NCC Group 2021 (older line); the only NCC-audited OPAQUE lib |
| `curve25519-dalek` | 4.1.3 | BSD-3-Clause | ristretto255 group ops | Widely used; post-RUSTSEC-2024-0344 |
| `argon2` | 0.5.3 | Apache-2.0/MIT | Argon2id KSF + blind-index KDF | RustCrypto; community-reviewed |
| `sha2` | 0.10.9 | Apache-2.0/MIT | SHA-512 (OPRF), SHA-256 (HKDF) | RustCrypto |
| `getrandom` | 0.2.17 | Apache-2.0/MIT | CSPRNG (incl. `js` on wasm) | Widely used |
| `rand` | 0.8.x | Apache-2.0/MIT | RNG (pinned 0.8 for opaque-ke's rand_core 0.6) | Widely used |
| `zeroize` | 1.8.2 | Apache-2.0/MIT | secret zeroization | Widely used |
| `voprf` | 0.5.0 | Apache-2.0/MIT | OPRF (opaque-ke dep) | RustCrypto |
| `serde`/`serde_json` | 1.x | Apache-2.0/MIT | wire (de)serialization | Widely used |
| `base64` | 0.22 | Apache-2.0/MIT | blob/index encoding | Widely used |
| `thiserror` | 1.x | Apache-2.0/MIT | error types | Widely used |

### Rust — `tessera-wasm` (browser core, in `tessera-ts`)
| Crate | Version | License | Role |
|-------|---------|---------|------|
| `wasm-bindgen` | 0.2.122 | Apache-2.0/MIT | JS↔WASM bindings |
| `getrandom` | 0.2.17 (`js`) | Apache-2.0/MIT | wasm CSPRNG via `crypto.getRandomValues` |
| `zeroize` | 1.x | Apache-2.0/MIT | zeroize WASM-held key copies |
| `ciphera-tessera` | path/git | Apache-2.0 | the shared OPAQUE + blind-index core |

### Go — `tessera-go`
| Module | Version | License | Role |
|--------|---------|---------|------|
| `golang.org/x/crypto` | v0.52.0 | BSD-3-Clause | Argon2id (`argon2`) | 
| Go stdlib `crypto/*` (`aes`, `cipher`, `hkdf`, `sha256`, `rand`) | go 1.25 | BSD-3-Clause | AES-256-GCM, HKDF, SHA-256 | Trail of Bits (stdlib crypto; 6 findings, addressed) |

### TypeScript — `@ciphera-net/tessera`
| Package | Version | License | Role |
|---------|---------|---------|------|
| `@scure/bip39` | 1.6.0 | MIT | BIP-39 recovery phrase | 
| `@noble/hashes` | 1.8.0 | MIT | hashing (transitive via @scure) |
| `@scure/base` | 1.2.6 | MIT | base encodings (transitive) |
| WebCrypto (`crypto.subtle`) | platform | — | AES-256-GCM, HKDF, non-extractable keys |
| _dev:_ `vitest`, `@playwright/test`, `typescript`, `tsx` | — | MIT/Apache | tests / type-check / vector generator |

---

## 3. v2 dependencies (named now, audited before use)

For the post-quantum hybrid (v2, asymmetric paths only — v1 vault content is already PQ-safe):
`crypto/mlkem` (Go stdlib, BSD-3, FIPS-203, Trail-of-Bits audited) server-side; `@noble/post-quantum`
(MIT, **self-audited only** — a third-party audit is a precondition for any key-path use) browser-side.

---

## 4. References

[`SELF-AUDIT.md`](./SELF-AUDIT.md) · [`SPEC.md`](./SPEC.md) · [`AUDIT-SCOPE.md`](./AUDIT-SCOPE.md).
