# Tessera Protocol & Wire Specification — v1 (suite `0x01`)

> **Status:** Self-reviewed by the Ciphera team; NOT independently audited.

This is the human-readable specification of the Tessera v1 cryptographic contract: the OPAQUE auth suite,
the blind index, the vault and VMK-wrap envelopes, the sidecar wire protocol, and the encodings. The
**machine-checked** pinned parameters and the conformance procedure live in
[`../conformance/schema.md`](../conformance/schema.md) and
[`../conformance/CONFORMANCE.md`](../conformance/CONFORMANCE.md); where this document and those disagree,
the conformance kit is authoritative (it is executed in CI).

**Suite identifier.** Every versioned blob is prefixed with a 1-byte suite id. v1 is `0x01`. A change to
any pinned parameter or wire layout requires a new suite byte (`0x02`, …) and a bumped kit version; an
implementation MUST reject a suite it does not implement rather than guess.

---

## 1. OPAQUE authentication (RFC 9807)

**Cipher suite (fixed — no agility at the OPAQUE layer):** RFC 9807 recommended configuration #1 —
ristretto255-SHA512 OPRF, TripleDH key exchange, Argon2id KSF. (`suite.rs`:
`OprfCs = Ristretto255`, `KeyExchange = TripleDh<Ristretto255, Sha512>`, `Ksf = Argon2`.)

**KSF (key-stretching function):** Argon2id, version `0x13` (19), `m = 65536 KiB` (64 MiB), `t = 3`,
`p = 1`. The KSF is applied **client-side** inside `Client{Registration,Login}::finish` — it is *not*
run in the sidecar, so it is pinned at the first production registration (the browser we build), not by
the server. Both the WASM client and the native sidecar compile the **same** `opaque-ke` core, so wire
interoperability holds by construction (proven by the live WASM↔sidecar handshake gate, not by two
libraries agreeing).

**`export_key`.** OPAQUE yields a client-only `export_key` (64 bytes, `Output<Sha512>`) at `finish`. It
is the root from which the browser wraps the vault key. It is **client-only**: it is never transmitted
and never logged (see §6, ZK boundary).

---

## 2. Blind index (account lookup)

A deterministic, privacy-preserving lookup key derived from the email, computed **client-side**.

- **KDF:** Argon2id, version `0x13`, `m = 65536 KiB`, `t = 3`, `p = 1`, output 32 bytes. (`p = 1` is a
  parity requirement: browser/WASM Argon2 builds are single-lane and may clamp `p > 1`, which would
  diverge from a multi-lane native build.)
- **Salt:** the fixed, public, versioned domain-separation string `tessera/blind-index/v1` (UTF-8, no
  NUL). Not per-user — the index must be deterministic to function as a lookup key.
- **Normalization (parity contract):** `lower(trim(email))` using **Unicode case folding** (Go
  `strings.ToLower` / Rust `str::to_lowercase`), applied trim-then-lower. **No** Unicode NFC and **no**
  IDNA/punycode in v1 (a documented limitation, pinned as conformance data).
- **Encoding:** base64url **unpadded** (Go `base64.RawURLEncoding`).
- **Dual use:** the blind index doubles as the OPAQUE `credential_identifier`, so the server finds the
  record without ever seeing the email.

**Security boundary.** The blind index MUST be computed client-side. The server MUST NOT call the
blind-index function on any value received over the network — doing so pulls the plaintext email into
server memory/logs and voids the zero-knowledge guarantee. (It is also a memory-DoS hazard: each call
holds 64 MiB for the Argon2id computation.)

---

## 3. Vault envelope v1

Seals a record under a per-context key. Layout (89-byte minimum, empty plaintext):

```
[0x01][nonceW 12B][AES-256-GCM(KEK, DEK) = 48B][nonceC 12B][AES-256-GCM(DEK, plaintext)]
```

| Field | Size | Notes |
|-------|------|-------|
| version | 1 | `0x01`; any other → `UnsupportedVersion` |
| nonceW | 12 | random; KEK-wraps the DEK |
| wrappedDEK | 48 | AES-256-GCM(KEK, DEK) = 32B ct + 16B tag |
| nonceC | 12 | random; DEK-encrypts the plaintext |
| ciphertext | ≥16 | AES-256-GCM(DEK, plaintext) = len(pt) + 16B tag |

- **KEK** = `HKDF-SHA-256(IKM = vaultKey, salt = 32 zero bytes, info = "tessera/vault/v1/record/" ‖
  utf8(context), L = 32)`. The 32-zero salt matches Go `hkdf.Key(…, nil, …)` (RFC 5869 §2.2 nil→HashLen
  zeros; SHA-256 HashLen = 32). An implementation that uses a genuinely empty (len-0) salt derives a
  different KEK and fails to open any envelope.
- **DEK** = fresh random 32 bytes per seal.
- **AAD** = `[0x01] ‖ utf8(context)`, bound into **both** GCM operations (wrap and content) — gives
  version-downgrade and context-substitution resistance.
- **`context`** (record type, optionally a record identity e.g. `address:user-123`) is **required** and
  **not stored** in the envelope; the caller must supply the same context to open. Each context derives
  an independent KEK (key separation): a blob sealed under one context cannot open under another.
- **Splice resistance:** the two layers are bound through the DEK — one envelope's wrappedDEK cannot
  open another's content.
- **Error model (oracle-free):** `open` returns a single generic `Malformed` for a too-short envelope, a
  wrong key, a wrong context, or any failed authentication tag; only an unrecognized version byte yields
  the distinct `UnsupportedVersion`. No decryption oracle.

---

## 4. VMK-wrap envelope v1 (browser-only)

The long-lived vault key is a random 32-byte **VMK** held as a non-extractable WebCrypto `CryptoKey`,
wrapped once per unlock method (`opaque` / `recovery` / `webauthn`). This layer exists **only** in the
browser SDK (the Go server SDK has no VMK). Single-layer envelope (61 bytes):

```
[0x01][nonce 12B][AES-256-GCM(wrapKEK, VMK) = 48B]
```

- **wrapKEK** = `HKDF-SHA-256(IKM = methodSecret, salt = 32 zero bytes, info = "tessera/vmk-wrap/v1/" ‖
  utf8(method), L = 32)`.
- **AAD** = `[0x01] ‖ utf8("tessera/vmk-wrap/v1/" ‖ method)` (binds version + method).
- The `methodSecret` is the OPAQUE `export_key` (opaque), the BIP-39 recovery entropy (recovery), or the
  WebAuthn-PRF output (webauthn). Adding or resetting a method only re-wraps the VMK — the vault content
  is never re-encrypted.

---

## 5. Sidecar wire protocol (server-internal)

`tessera-go` calls the Rust sidecar over a **local Unix domain socket** (no TCP). This wire is
**server-internal** — it is not the client-facing wire and is not part of the zero-knowledge boundary
(see §6).

**Framing.** `[u32 big-endian length][payload]`. Max frame = `1 MiB` (`MAX_FRAME`); a larger length
prefix is rejected before allocation.

**Messages.** JSON, internally tagged. Requests carry an `op` field (snake_case variant name); responses
carry a `result` field. OPAQUE blobs are base64-**STANDARD**.

| Request `op` | Fields | Response `result` | Fields |
|---|---|---|---|
| `register_start` | `request_b64`, `credential_id` | `register_start` | `response_b64` |
| `register_finish` | `upload_b64` | `register_finish` | `password_file_b64` |
| `login_start` | `request_b64`, `password_file_b64` (nullable), `credential_id` | `login_start` | `login_id`, `response_b64` |
| `login_finish` | `login_id`, `finalization_b64` | `login_finish` | `session_key_b64` |
| (any failure) | — | `error` | `code`, `message` |

- `login_start.password_file_b64 = null` signals an **unknown account**; the sidecar lets `opaque-ke`
  produce a timing-safe fake response, so the protocol never reveals whether an account exists.
- `login_finish` returns only `session_key_b64` — structurally **no `export_key`** crosses this wire.

**Stable error codes** (`error.rs`), so clients branch on class without parsing human messages:

| `code` | Meaning | Intended HTTP |
|--------|---------|---------------|
| `unknown_login` | unknown `login_id` | 400 |
| `invalid_credentials` | OPAQUE `InvalidLoginError` (wrong password) | 401 |
| `bad_request` | malformed/tampered OPAQUE message or bad base64 (`SerializationError`/`SizeError`/`ReflectedValueError`) | 400 |
| `internal` | `LibraryError` / I/O / internal crypto fault | 500 |

---

## 6. Zero-knowledge boundary

What the **client** (browser) holds vs. transmits:

- **Holds (client-only, never transmitted):** the password, the OPAQUE `export_key`, the raw VMK, the
  recovery phrase, the WebAuthn-PRF output.
- **Transmits:** OPAQUE protocol blobs, the `credential_id` (blind index), and the **encrypted** VMK-wrap
  blobs. The browser `registerFinish` returns **void** — the password file is produced server-side (by
  the sidecar's `register_finish`) and stored server-side; the client never receives it.
- **Server-internal only:** the OPAQUE password file flows sidecar→`tessera-go` over the local UDS
  (§5) and is persisted by the application. It is the server's stored OPAQUE record — by OPAQUE's design
  it is **not** password-equivalent — and it never reaches the client. This is not a ZK-boundary
  crossing.

The server is a *curious/compromised server* adversary in the threat model: it never learns the
password, the vault contents, or the email plaintext.

---

## 7. Encodings

| Context | Encoding |
|---------|----------|
| OPAQUE blobs on the sidecar wire | base64 **STANDARD** (Go `base64.StdEncoding`) |
| Blind index / `credential_id` | base64url **unpadded** (Go `base64.RawURLEncoding`) |
| Conformance vector hex fields | lowercase hex |

---

## 8. Out of scope (v1)

No new primitives; no post-quantum algorithms (v2 readiness only — versioned envelopes + a KEM/KDF seam);
no relay/envoy E2E path (v2). Offline OPAQUE handshake vectors are out of scope for conformance (interop
is by-construction + the live gate). See [`../conformance/CONFORMANCE.md`](../conformance/CONFORMANCE.md).

---

## 9. References

- Pinned parameters (machine-checked): [`../conformance/schema.md`](../conformance/schema.md)
- Conformance procedure: [`../conformance/CONFORMANCE.md`](../conformance/CONFORMANCE.md)
- Parity evidence: [`PARITY.md`](./PARITY.md)
- Threat model: [`THREAT-MODEL.md`](./THREAT-MODEL.md)
- RFC 9807 (OPAQUE), RFC 5869 (HKDF), RFC 9106 (Argon2).
