# Tessera Conformance Kit — Procedure

This document is the **language-neutral conformance procedure** for the Tessera cryptographic contract.
Any implementation (Go, TypeScript/WASM, or a future Rust/Python/Swift port) can self-check against the
checked-in vectors with **no help from us**: reproduce the deterministic values byte-for-byte, open the
sealed envelopes, and reject the malformed ones with the correct error class.

The pinned algorithm constants live in [`schema.md`](./schema.md); this document defines *what an
implementation must do* with each vector file.

---

## Files

All vector files live in `conformance/vectors/` and begin with a versioned header object:

```json
{ "kitVersion": "1.0.0", "suite": "0x01", "generatedBy": "...", "vectors": [ ... ] }
```

| File | Verifies | Determinism |
|------|----------|-------------|
| `blind-index.json` | Blind-index derivation + email normalization | **Byte-exact** (deterministic Argon2id) |
| `vault.json` | Vault envelope Open + KEK derivation | Open: round-trip · `kekHex`: **byte-exact** |
| `vault-negative.json` | Vault Open rejection semantics | Must-reject with the named error class |
| `vmk-wrap.json` | VMK-wrap envelope Open + wrap-KEK derivation (**browser-only**) | Open: round-trip · `wrapKekHex`: **byte-exact** |

**Generators** (maintainers only; verifiers do not regenerate): `blind-index.json` + `vault.json` +
`vault-negative.json` are produced by `tessera-go/harness/vectors/gen_go.go` (`go run -tags conformance
./harness/vectors --write`); `vmk-wrap.json` is produced by `tessera-ts/harness/vmk-vectors/gen_vmk.ts`.

---

## Normalization contract

The email normalization applied before the blind index is **`lower(trim(email))`** using **Unicode case
folding** — Go `strings.ToLower` / Rust `str::to_lowercase` semantics, **NOT** ASCII-only `tolower`. There
is **no** Unicode NFC normalization and **no** IDNA/punycode folding in v1 (a documented limitation, pinned
as data: see the `José@…` and `ZÜRICH@…` vectors). A port that uses ASCII-only lowercasing will diverge on
non-ASCII cased letters and fail the byte-exact check.

---

## Per-vector-type procedure

### `blind-index.json` — byte-exact
For each vector: compute the blind index of `email` and assert the base64url-**unpadded** result equals
`blindIndexBase64Url`, **character-for-character**. A single divergent byte is an implementation bug (wrong
Argon2id param, wrong normalization order, or wrong base64 alphabet/padding).

`normalizedEmail` is an **intermediate KAT**: implementations that expose their normalization step SHOULD
assert `normalize(email) == normalizedEmail` byte-for-byte (debugs the normalization layer in isolation).
Implementations that normalize *inside* an opaque core (e.g. the TS SDK normalizes in WASM) verify it
**transitively** — the case/whitespace-variant inputs collapse to the same `blindIndexBase64Url`.

### `vault.json` — Open-parity + KEK KAT
For each vector: import `vaultKeyHex`, `open(envelopeHex)` under `context`, and assert the recovered
plaintext equals `plaintextHex` byte-for-byte. Encryption is **non-deterministic** (random nonces), so the
`envelopeHex` is a *snapshot* — do not expect to reproduce it; only the **Open** direction is required.

`kekHex` is an **intermediate KAT**: `HKDF-SHA256(vaultKey, salt = 32 zero bytes, info =
"tessera/vault/v1/record/" ‖ context, L = 32)`. Implementations that can expose the raw per-context KEK
SHOULD assert it equals `kekHex` (debugs the HKDF layer before the AES-GCM round-trip). Implementations
where the KEK is a **non-extractable** key (e.g. the TS SDK's WebCrypto `CryptoKey`) verify it
**transitively** via Open-parity — they cannot read the KEK bytes by design.

### `vault-negative.json` — must-reject with the right error class
For each vector: `open(envelopeHex)` under `context` MUST fail. Assert the error matches `expect`:
- `"UnsupportedVersion"` — the version byte is not `0x01` (a distinct, non-secret rejection).
- `"Malformed"` — a too-short envelope, a tampered tag, a wrong key, or a wrong context. These are
  deliberately **indistinguishable** (one error class): no decryption oracle.

### `vmk-wrap.json` — browser-only, Open-parity + wrap-KEK KAT
The VMK-wrap envelope exists **only in the browser SDK** (the Go server SDK has no VMK layer); there is no
Go side. For each vector: `unwrapVmkRaw(blobHex)` under (`methodSecretHex`, `method`) and assert the
recovered VMK equals `vmkHex`. `wrapKekHex` is an intermediate KAT: `HKDF-SHA256(methodSecret, salt = 32
zero bytes, info = "tessera/vmk-wrap/v1/" ‖ method, L = 32)`, verified byte-exact by ports that expose the
wrap-KEK, else transitively (the TS SDK's wrap-KEK is non-extractable).

---

## Versioning / bump rule

`kitVersion` is the kit's semver; `suite` is the on-the-wire suite identifier (`0x01` in v1). **Any change
to a pinned parameter or wire format requires a new `suite` byte and a bumped `kitVersion`** — the vectors
are then regenerated and re-verified. Implementations MUST reject a `suite` they do not implement rather
than guess.

---

## Out of scope

**OPAQUE handshake vectors** are intentionally out of this kit. OPAQUE interop is proven *by construction*
(the TS SDK and the Go sidecar share one compiled `opaque-ke` core) and by the live WASM↔sidecar handshake
gate, not by offline message vectors — serializing `opaque-ke`'s internal OPRF/AKE state is impractical
without owning the library internals. See `schema.md` for the full rationale.

---

## How to run

**Go** (server SDK; verifies blind-index byte-exact, normalized-email KAT, KEK KAT, vault Open, negatives):

```
# with the core repo checked out as a sibling, from the tessera-go module root:
TESSERA_VECTORS_DIR=/path/to/tessera/conformance/vectors \
  go test -tags conformance -run TestConformance ./...
```

**TypeScript/WASM** (browser SDK; verifies blind-index byte-exact, vault Open + edges, negatives, VMK
Open-parity; KEK/wrap-KEK/normalization verified transitively):

```
cd packages/tessera-ts && npx vitest run test/vectors.test.ts
```

Both run in CI on every push (tessera-go `conformance` job; tessera-ts `ts-tests` job), reading these
canonical vectors via a sibling checkout of this repo.
