# Tessera Self-Audit Report — Phase 4

> **Status:** Self-reviewed by the Ciphera team; **NOT independently audited.** This is an internal
> adversarial review, not a substitute for a third-party audit. It records what we tried to break, what
> held, what we found, what we fixed, and the limits we know remain.

**Date:** 2026-06-04 · **Reviewed:** `ciphera-tessera` (Rust core + sidecar), `tessera-go`, `tessera-ts`
(`@ciphera-net/tessera`) at the Phase-4 conformance-kit HEADs.

---

## 1. Scope & method

Full-surface review across the three repos, tiered by where exploitability lives (scoped from the threat
model — see [`THREAT-MODEL.md`](./THREAT-MODEL.md)), over 8 dimensions:

1. Zero-knowledge boundary 2. Cryptographic correctness 3. Secret hygiene 4. Oracle resistance &
constant-time 5. Process/memory boundary 6. Sidecar/server hardening 7. Supply chain 8. API
misuse-resistance.

**Methodology.** Each dimension was reviewed by an independent agent instructed to **actively refute**
each security claim by finding a counterexample in the actual source (not to rubber-stamp). Every raw
finding was then **independently verified** against source by a separate agent before it counted (13
raw → 13 confirmed → 0 rejected). All cryptographic authorship, adjudication, and fixes were done by the
lead in the main thread; subagents reviewed only. Confirmed findings ran a **find → fix → re-verify**
loop; the re-verification (build/clippy/test green in each repo) is recorded with each fix.

---

## 2. Result summary

**0 critical, 0 high.** The cryptographic-correctness dimension returned **no findings** — all six core
claims (suite/KSF pinning, blind-index parity, vault envelope/AAD/HKDF-nil-salt equivalence, nonce
safety, key separation, splice resistance) were probed and upheld, corroborated by the conformance kit.
The 13 findings are hygiene, supply-chain, documentation-accuracy, and forward-compatibility issues — the
profile expected of code that already passed per-task two-stage review in Phases 1–3.

**8 remediated, 5 accepted as documented residuals.**

| ID | Dim | Sev | Title | Status |
|----|-----|-----|-------|--------|
| ZK-01 | zk-boundary | low | `Request` derives `Debug` without redacting `password_file_b64` | **Fixed** — core `587b41c` |
| ZK-02 | zk-boundary | nit | `client_helper` example prints `export_key` to stdout | **Fixed (annotated)** — go `f923804` |
| SH-01 | secret-hygiene | low | opaque-ke FinishResult copies of export/session key not zeroed | **Fixed** — core `587b41c` |
| SH-02 | secret-hygiene | low | recovery secret persists in `RecoverySession`; README overclaimed | **Fixed** — ts `2fb5a59` |
| ORC-001 | oracle-ct | nit | `Open` docstring omits `ErrEmptyVaultKey` | **Fixed** — go `f923804` |
| SD-01 | sidecar | nit | `serde_json::to_vec(..).expect` breaks no-panic invariant structurally | **Fixed** — core `587b41c` |
| SD-02 | sidecar | med | Nomad deploys sidecar by mutable tag, not digest | **Documented** (Phase-5 deploy) |
| SC-01 | supply-chain | med | GitHub Actions referenced by mutable tags, not SHAs | **Documented** (pin + Dependabot) |
| SC-02 | supply-chain | med | `wasm-pack` installed via unverified `curl\|sh` | **Fixed** — ts `2fb5a59` |
| SC-03 | supply-chain | low | core path-dep / CI checkout has no `ref:` pin | **Documented** (public-repo migration) |
| SC-04 | supply-chain | low | no automated CVE/advisory scanning in CI | **Documented** (CI-policy) |
| AMR-01 | api-misuse | low | VMK unwrap collapses unknown version into `Malformed` | **Fixed** — ts `2fb5a59` |
| AMR-02 | api-misuse | nit | `isPasskeySupported` probes platform-auth, not PRF | **Documented** (honest limit) |

---

## 3. Remediations (fixed + re-verified)

- **ZK-01** — replaced the blanket `#[derive(Debug)]` on `Request`/`Response` with manual `Debug` impls
  that redact `password_file_b64` and `session_key_b64`, so an accidental future `{:?}` log cannot leak
  the OPAQUE credential record or a session key. (core; clippy + 15/2/7 tests green.)
- **SH-01** — `register_finish`/`login_finish` (client) and `login_finish` (server) now explicitly
  `zeroize` the `export_key`/`session_key` `GenericArray` copies the opaque-ke FinishResult still holds
  after extraction (FinishResult is not `ZeroizeOnDrop` in 4.x). Added `zeroize` as a direct dep; the
  misleading "state types zeroize on drop" comment was corrected to distinguish state vs result types.
- **SD-01** — the sidecar's per-connection serialize now uses an `unwrap_or_else` fallback that emits a
  fixed `internal`-error frame instead of `.expect`-panicking, preserving the no-panic invariant
  structurally against a future non-serializable `Response` variant.
- **ORC-001** — `tessera-go` `Open` docstring now documents `ErrEmptyVaultKey`/`ErrEmptyContext` and
  notes they are caller-error signals independent of envelope content (not a decryption oracle).
- **ZK-02** — annotated the `tessera-go` integration CI step that `-v` is intentionally omitted so the
  `client_helper`'s ephemeral `export_key` stdout never lands in CI logs.
- **SH-02** — corrected the README/JSDoc overclaim ("recovery entropy … does not persist across calls")
  to accurately state that `recoverWithPhrase` retains the 32-byte recovery secret in the
  `RecoverySession`; added `RecoverySession.dispose()` to zero it when the caller does not `resetPassword`.
- **AMR-01** — `vmk.ts` `unwrapVmkRaw` now rejects an unknown version byte with the distinct
  `UnsupportedVersionError` (matching `vault.open`), not `MalformedEnvelopeError`; added a unit test.
- **SC-02** — replaced the three `curl … | sh` `wasm-pack` bootstraps with
  `cargo install wasm-pack --version 0.15.0 --locked` (version-pinned, crates.io-checksummed).

---

## 4. Accepted residuals (documented, not fixed in Phase 4)

- **SD-02 (med) — deploy-by-digest.** The Dockerfile pins base images by digest, but the Nomad job
  deploys the output image by a mutable tag. The fix (deploy by digest, recorded from CI, + registry
  tag-immutability) is a production deploy-pipeline change and belongs with **Phase 5 (dogfooding/deploy)**,
  not the SDK/kit scope of Phase 4.
- **SC-01 (med) — action SHA-pinning.** Every `uses:` is a mutable tag. The robust fix is to pin all
  actions to commit SHAs **and** enable Dependabot's `github-actions` updates to keep them current;
  pinning without Dependabot trades a tag-mutation risk for a stale-action risk. Scheduled as one
  deliberate CI-hardening batch (the two third-party actions, `dtolnay/rust-toolchain` and
  `Swatinem/rust-cache`, are the priority).
- **SC-03 (low) — core `ref:` pin.** `tessera-ts` consumes the core via an unversioned path dep and the
  CI checks out core `HEAD` with no `ref:`. This is the already-planned migration to a pinned git-rev
  dep at public-repo time (the Cargo.toml comment marks it). Private repos today ⇒ no external-injection
  exposure; the gap is reproducibility, addressed by that migration.
- **SC-04 (low) — advisory scanning.** No `cargo audit`/`cargo deny`/`npm audit` step runs in CI.
  Recommended follow-up: add advisory scanning (or enable GitHub Dependabot security alerts) on all three
  repos so a newly-published CVE against a pinned crypto dep is caught automatically.
- **AMR-02 (nit) — `isPasskeySupported` granularity.** It probes platform-authenticator availability, not
  WebAuthn-PRF support (definitive PRF support is only known after a real ceremony). Documented as a
  conservative gate; `evaluatePrf` fails loudly if PRF is absent. An honest limit, not a silent failure.

---

## 5. Residual limits (inherent; carried into the threat model)

These are **not** defects to fix — they are honest boundaries of the design, documented so no one
over-trusts the system. They are reproduced in [`THREAT-MODEL.md`](./THREAT-MODEL.md).

- **Non-extractable `CryptoKey` is an API-layer guard, NOT process isolation.** A compromised page
  (XSS, malicious dependency/extension) can still *use* the key to seal/open; it cannot export the raw
  bytes via the WebCrypto API. Tessera resists XSS-grade attackers, not native code in the tab's process.
- **Memory zeroing is best-effort.** `export_key`/VMK/DEK/KEK transit WASM/JS linear memory and are
  zeroed in `finally`/`defer`, but GC may have copied buffers and AES round-key schedules inside the
  cipher objects are unreachable for zeroing. Never persisted, never on the wire — but not guaranteed
  erased. (The Rust FinishResult intermediates are now zeroed too — SH-01.)
- **The recovery phrase string is immutable and un-zeroable** (JS strings). Show once, minimise lifetime.
- **Constant-time execution is not fully achievable in TS/WASM** (JIT). The vault `open` collapses
  wrong-key/context/tamper into one error (no decryption oracle) and the sidecar's unknown-account path
  is timing-safe, but the TS orchestration layer relies on the underlying Rust/WebCrypto primitives for
  timing safety — it is not itself constant-time.
- **GCM random-nonce safety is application-scale.** Content nonces sit under single-use DEKs (zero reuse
  surface); wrap nonces sit under per-(key,context) KEKs, well below the NIST random-nonce bound at
  realistic record counts — not an unbounded guarantee.
- **No independent third-party audit.** This report is the only review to date.
