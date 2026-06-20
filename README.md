# Tessera

Open-source **zero-knowledge identity**: an [OPAQUE](https://www.rfc-editor.org/rfc/rfc9807)
asymmetric PAKE core plus a client-encrypted vault. Your password never reaches the server —
not even hashed — and the key that encrypts your account data is derived on your device and
never leaves it.

This repository (`ciphera-net/tessera`) is the **Rust core**: the OPAQUE cipher suite, the
`tessera-sidecar` binary that runs the server side of the handshake, the cross-language
conformance kit, and the specification & audit documents. It powers Ciphera ID, and it is
built to be self-hosted and adopted by anyone.

> [!NOTE]
> **Security status: self-reviewed; not yet independently audited.** Tessera has had a rigorous
> internal self-audit (see [`docs/SELF-AUDIT.md`](./docs/SELF-AUDIT.md)). Read [`docs/SPEC.md`](./docs/SPEC.md)
> and [`docs/THREAT-MODEL.md`](./docs/THREAT-MODEL.md), and review the code, before relying on it
> for anything critical.

## What it provides

- **OPAQUE authentication** — the password is never sent to the server in any form. Login is a
  cryptographic proof of knowledge; the server stores only an opaque registration record.
- **Client-encrypted vault** — account data (e.g. email, profile) is sealed on the device under
  a Vault Master Key (VMK) the server never holds; the server stores only ciphertext.
- **Recovery & re-key** — VMK-wrap envelopes (password, recovery phrase, passkey/PRF) let users
  recover or rotate credentials without the server ever seeing key material.
- **Blind index** — accounts are looked up by an irreversible keyed hash of the email, so the
  server can find an account without storing the address.

## Cryptographic suite (v1, suite byte `0x01`)

| Component | Choice |
|-----------|--------|
| OPAQUE | RFC 9807 configuration #1 |
| OPRF | ristretto255-SHA-512 |
| Key exchange | 3DH (TripleDH) |
| KSF (key-stretching) | Argon2id, v0x13, **m = 64 MiB, t = 3, p = 1** (pinned, client-side) |
| Vault / VMK-wrap | AES-256-GCM with HKDF-SHA-256, AAD-bound to a version + context |

Parameters are **pinned** (not library defaults) and verified byte-for-byte across the Rust, Go,
and TypeScript implementations by the [conformance kit](./conformance/). All primitives are
delegated to vetted libraries ([`opaque-ke`](https://crates.io/crates/opaque-ke), `curve25519-dalek`,
`argon2`, `sha2`); the crate is `#![forbid(unsafe_code)]` and contains no hand-rolled cryptography.

## The Tessera repos

| Repo | What |
|------|------|
| [`ciphera-net/tessera`](https://github.com/ciphera-net/tessera) (this repo) | Rust OPAQUE core + `tessera-sidecar` + conformance kit + docs |
| [`ciphera-net/tessera-go`](https://github.com/ciphera-net/tessera-go) | Go server SDK |
| [`ciphera-net/tessera-ts`](https://github.com/ciphera-net/tessera-ts) (`@ciphera-net/tessera`) | Browser SDK (WASM OPAQUE + WebCrypto vault) |

## Build & test

```bash
cargo build --release          # builds the library + the tessera-sidecar binary
cargo test                     # unit + integration (real-socket round-trip) tests
cargo fmt --check && cargo clippy --all-targets
```

## Running the sidecar

`tessera-sidecar` answers the server side of the OPAQUE handshake over a Unix socket. It requires
a **ServerSetup** (the long-term OPRF secret), which you generate once per deployment and provide
at startup from your own secrets manager:

```bash
# Generate once; store the output in your secrets manager. Keep it 0400 and OFF the repo.
tessera-sidecar gen-setup /path/to/server-setup.bin

# Run the socket server: serve <socket> <setup-path>
tessera-sidecar serve /run/tessera/tessera.sock /path/to/server-setup.bin
```

Optional tuning via env vars: `TESSERA_FRAME_DEADLINE_MS`, `TESSERA_LOGIN_TTL_MS`,
`TESSERA_MAX_CONNECTIONS`.

> The ServerSetup is the only long-term server secret. It must **never** be committed to source
> control — `.gitignore` excludes `*.bin` / `server-setup*` as a guard. Treat its loss/exposure
> the way you would any root key.

## Documentation

See [`docs/`](./docs/): [SPEC](./docs/SPEC.md), [THREAT-MODEL](./docs/THREAT-MODEL.md),
[SELF-AUDIT](./docs/SELF-AUDIT.md), [PARITY](./docs/PARITY.md), [DEPENDENCIES](./docs/DEPENDENCIES.md),
[AUDIT-SCOPE](./docs/AUDIT-SCOPE.md), and [SECURITY](./docs/SECURITY.md).

## Security

Please report vulnerabilities per [`docs/SECURITY.md`](./docs/SECURITY.md) (responsible disclosure
to security@ciphera.net). Do not open public issues for security reports.

## License

Licensed under the [Apache License, Version 2.0](./LICENSE). You may self-host, modify, and
redistribute it, including in proprietary products, subject to the license terms.

## Export notice

This distribution includes cryptographic software (OPAQUE / ristretto255 / Argon2id / AES-256-GCM).
It is published as open-source, publicly-available software. Under EU Regulation (EU) 2021/821
(the dual-use recast), software that is "in the public domain" / publicly available is generally
outside the scope of export controls. Your own local laws may still apply to your use.
