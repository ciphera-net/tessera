# Tessera Conformance Vectors — Schema and Pinned Constants

This document defines the vector files in this directory, all pinned algorithm constants, and the
parity guarantees each vector type provides. For the language-neutral conformance **procedure** (what
an implementation must DO with each file), see [`CONFORMANCE.md`](./CONFORMANCE.md).

## Files

Each file begins with a versioned header object — `{ "kitVersion", "suite", "generatedBy", "vectors": [...] }`.

| File | Purpose | KAT fields |
|------|---------|-----------|
| `blind-index.json` | Blind-index parity (byte-exact, deterministic) | `normalizedEmail` |
| `vault.json` | Vault envelope (Open-parity; see note below) | `kekHex` |
| `vault-negative.json` | Vault rejection vectors (`expect`: `UnsupportedVersion` \| `Malformed`) | — |
| `vmk-wrap.json` | VMK-wrap envelope — **browser-only** (no Go side); Open-parity | `wrapKekHex` |

Verifiers: `tessera-go` `conformance_test.go` (`go test -tags conformance`, white-box) and
`tessera-ts` `packages/tessera-ts/test/vectors.test.ts` (vitest). Generators (maintainers only):
`tessera-go/harness/vectors/gen_go.go` (blind-index / vault / negative; authoritative + round-trip
self-check) and `tessera-ts/harness/vmk-vectors/gen_vmk.ts` (vmk-wrap; self-checks the wrap-KEK).

---

## Blind-Index Algorithm — Pinned Constants

All implementations MUST use these exact parameters. Any change requires a bumped salt label and
a versioned migration of all affected accounts.

| Parameter | Value | Note |
|-----------|-------|------|
| KDF | Argon2id | RFC 9106 variant (requires data-independent memory access) |
| Version | `0x13` (19) | MUST be specified explicitly — do not accept other versions |
| Time (t) | `3` | Iterations |
| Memory (m) | `65536 KiB` (64 MiB) | `64 * 1024` KiB |
| Parallelism (p) | `1` | Parity requirement — see note below |
| Output length | `32` bytes | |
| Salt | `"tessera/blind-index/v1"` (UTF-8 bytes, no NUL) | Fixed, public, versioned domain-separation salt |
| Encoding | base64url **unpadded** | Go `base64.RawURLEncoding`; replace `+→-`, `/→_`, strip `=` padding |

**Normalization (PART OF CONTRACT — must be applied in this order):**

1. `TrimSpace` — strip leading and trailing ASCII whitespace
2. `ToLower` — fold to lowercase (ASCII; no Unicode NFC / IDNA punycode in v1)

The normalized email is the Argon2id password argument. The salt is not per-user — the index must
be deterministic to function as a lookup key; the domain-separation salt binds it to this version.

**Why p=1:** Common browser/WASM Argon2 builds run single-threaded and may silently clamp `p>1` to
`p=1`, yielding a DIFFERENT output from a native multi-lane build. Pinning `p=1` guarantees the
browser and server compute byte-identical indices across all implementations.

### Parity guarantee

Blind-index vectors are **byte-EXACT and deterministic**. An implementation MUST reproduce the
`blindIndexBase64Url` value for the given `email` (including any whitespace / case) character-for-
character. A single divergent byte is an implementation bug — most likely a wrong parameter, a
different normalization order, or incorrect base64url encoding (e.g. standard vs. URL alphabet, or
padding retained).

---

## OPAQUE KSF — Pinned Constants (documentation only)

The OPAQUE password-hardening KSF uses the same Argon2id suite, applied at `register_finish` and
`login_finish` on the client. These constants are documented here for completeness; OPAQUE handshake
vectors are out of scope (see note below).

| Parameter | Value |
|-----------|-------|
| KDF | Argon2id `0x13` |
| Memory (m) | `65536 KiB` (64 MiB) |
| Time (t) | `3` |
| Parallelism (p) | `1` |
| Output length | KSF output length is supplied by the OPAQUE protocol (`output_len = None` → uses the OPAQUE-internal length) |

---

## Vault Envelope v1 — Layout and Pinned Constants

```
[0x01][nonceW 12B][AES-256-GCM(KEK, DEK) = 48B][nonceC 12B][AES-256-GCM(DEK, msg)]
```

Minimum envelope size (empty plaintext): **89 bytes**
`= 1 (version) + 12 (nonceW) + 48 (wrappedDEK) + 12 (nonceC) + 16 (empty-msg tag)`

| Field | Size | Description |
|-------|------|-------------|
| Version | 1 B | `0x01` — reject any other value with `UnsupportedVersionError` |
| nonceW | 12 B | Random nonce for KEK wrapping of DEK |
| wrappedDEK | 48 B | AES-256-GCM(KEK, DEK): 32B ciphertext + 16B tag |
| nonceC | 12 B | Random nonce for DEK encryption of plaintext |
| ciphertext | ≥ 16 B | AES-256-GCM(DEK, plaintext): `len(plaintext)` B ciphertext + 16B tag |

**Key derivation (KEK):**

```
KEK = HKDF-SHA-256(
  IKM  = vaultKey,
  salt = 32 zero bytes,           // RFC 5869 §2.2 nil-salt expansion; Go stdlib hkdf.Key(nil) → 32 zeros
  info = "tessera/vault/v1/record/" ‖ utf8(context),
  L    = 32
)
```

The `salt = 32 zero bytes` is intentional and matches Go's `hkdf.Key(sha256.New, vaultKey, nil, ...)`.
RFC 5869 §2.2 specifies that a nil salt is replaced by a HashLen-zero string; SHA-256 HashLen = 32.
An implementation that uses a genuinely empty (`len=0`) salt instead of 32 zero bytes will derive a
different KEK and fail to open any envelope.

**AAD** (bound into BOTH GCM operations — wrap and content):

```
AAD = [0x01] ‖ utf8(context)
```

Using the same AAD for both GCM operations binds the version byte and the record context to every
authentication tag, preventing version downgrade and context substitution attacks. The context is
NOT stored in the envelope; the caller must supply it on both `seal` and `open`.

**Key separation:** Each record type (e.g. `"address"`, `"totp"`) derives an independent KEK via the
HKDF info string. An envelope sealed under `"address"` cannot be opened under `"totp"`.

### Parity guarantee

Vault vectors are **Open-parity only**. Encryption is non-deterministic (both `nonceW` and `nonceC`
are random); the `envelopeHex` in vault.json is NOT reproducible byte-for-byte — it is a snapshot
sealed by the Go generator. An implementation must verify that it can OPEN `envelopeHex` using the
given `vaultKeyHex` and `context` and recover `plaintextHex` exactly. It must also verify its own
round-trip (seal then open recovers plaintext). The existing vault-parity.test.ts provides live
Go↔TS bidirectional round-trip coverage.

---

## Out of Scope

**OPAQUE handshake vectors** are out of scope for this test kit. OPAQUE interop is proven by
construction (the TS SDK drives the Rust sidecar over the JSON/framing wire protocol, with the
client and server sharing the same ciphersuite) and by the live handshake gate in
`harness/handshake/handshake.test.mjs`. Offline OPAQUE message vectors would require serializing
internal OPRF/AKE state that the `opaque-ke` library does not expose publicly, and are therefore
impractical without owning the library internals.
