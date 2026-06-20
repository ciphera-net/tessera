# Tessera Threat Model — v1

> **Status:** Self-reviewed by the Ciphera team; not yet independently audited.

This is the consolidated threat model for Tessera v1 (suite `0x01`). It states the adversaries Tessera
defends against, the guarantees it provides, and — as importantly — the honest limits it does **not**
exceed. It merges the design threat model with the residual limits confirmed by the self-audit
([`SELF-AUDIT.md`](./SELF-AUDIT.md)).

---

## 1. In-scope adversaries (defended)

- **Curious or compromised server** — the zero-knowledge guarantee. The server stores only the OPAQUE
  credential record and client-encrypted vault blobs; it never learns the password, the vault contents,
  or the email plaintext. (The blind index is computed client-side; the server looks up by it without
  seeing the email.)
- **Network attacker** — mutual authentication. OPAQUE (RFC 9807) gives a mutually-authenticated session;
  a network attacker cannot impersonate the server or learn the password, and cannot replay across the
  encrypted-envelope contexts (AAD binds version + record context).
- **XSS-grade in-page attacker** — the vault key and VMK live as **non-extractable** WebCrypto keys, so
  malicious in-page JavaScript can *ask* them to seal/open but cannot read their raw bytes.

## 2. Out-of-scope adversaries (NOT defended)

- **Full render-process / native-code compromise** of the browser tab (can reach key material in process
  memory regardless of the non-extractable API).
- **Spectre-class / micro-architectural side channels.**
- **Malicious authenticator hardware** (for the WebAuthn-PRF path).

---

## 3. Guarantees that hold (verified by the self-audit)

- **ZK boundary intact:** `export_key`, the raw VMK, and the password file never cross the client wire,
  are not returned to the browser, and are not logged. `registerFinish` returns void; the server's
  login-finish yields only a session key. (Self-audit dimension 1 — upheld; ZK-01 hardened the latent
  Debug-log path.)
- **Cryptographic construction correct:** suite/KSF pinned identically across languages
  (Argon2id/V0x13/64 MiB/t3/p1); blind index byte-exact Go↔Rust; vault envelope, AAD, and HKDF-nil-salt
  byte-identical Go↔TS; GCM nonces safe; per-context key separation; splice resistance. (Dimension 2 —
  no findings; corroborated by the conformance kit, see [`PARITY.md`](./PARITY.md).)
- **No decryption oracle:** vault/VMK `open` collapse wrong-key / wrong-context / tamper / short-buffer
  into a single `Malformed` error; only an unknown version byte is a distinct (non-secret) rejection.
- **User-enumeration safe:** the sidecar's unknown-account login path returns a timing-safe dummy
  response (no early return).
- **Secret hygiene:** transient secrets are zeroed in `finally`/`defer` on all paths, including (after
  SH-01) the opaque-ke FinishResult intermediates.

---

## 4. Honest limits (residual; by design, not defects)

The published artifacts must state these, and do:

- **Non-extractable `CryptoKey` is an API-layer guard, NOT process isolation.** A compromised page can
  still *use* the key; it cannot export the raw bytes via WebCrypto. Tessera resists XSS-grade
  attackers, not native code executing in the tab's process.
- **Memory zeroing is best-effort.** Key material transits WASM/JS linear memory and is zeroed after
  use, but GC may copy buffers and AES round-key schedules inside cipher objects are unreachable. Never
  persisted, never on the wire — but not guaranteed erased.
- **The recovery phrase string is immutable / un-zeroable** (JS strings). The 32-byte entropy derived
  from it is zeroed; on the recover path it persists in the `RecoverySession` until `resetPassword` or
  `dispose()` (SH-02). Show the phrase once; minimise its lifetime.
- **Constant-time execution is not fully achievable in TS/WASM.** The orchestration layer relies on the
  underlying Rust/WebCrypto primitives for timing safety; it is not itself constant-time.
- **GCM random-nonce safety is application-scale**, not unbounded (content nonces under single-use DEKs;
  wrap nonces under per-(key,context) KEKs, below the NIST random-nonce bound at realistic counts).
- **Envelope binding is type/identity, NOT temporal.** The per-context KEK + AAD prevent substituting a
  blob across record types or identities, but do **not** prevent **rollback** (replacing a blob with an
  older value of the *same* context). Freshness/versioning is an application/DB-layer concern.
- **Harvest-now-decrypt-later applies to asymmetric paths only.** v1 vault content is AES-256-GCM
  (already PQ-safe: Grover only halves the key strength → 128-bit PQ). HNDL exposure is on the future
  relay/asymmetric paths (v2); v1 ships PQ-*readiness* (versioned envelopes + a KEM/KDF seam), not PQ
  algorithms.
- **No independent third-party audit.** A rigorous internal self-audit is not a substitute (see
  [`SELF-AUDIT.md`](./SELF-AUDIT.md)). The accepted-residual hardening items (deploy-by-digest, action
  SHA-pinning, advisory scanning) are tracked there.

---

## 5. References

[`SELF-AUDIT.md`](./SELF-AUDIT.md) · [`SPEC.md`](./SPEC.md) · [`PARITY.md`](./PARITY.md) ·
[`DEPENDENCIES.md`](./DEPENDENCIES.md) · [`AUDIT-SCOPE.md`](./AUDIT-SCOPE.md).
