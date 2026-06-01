//! The Tessera OPAQUE cipher suite and server-setup helpers.
//!
//! The cipher suite is fixed (no algorithm agility at the OPAQUE layer): RFC 9807
//! recommended configuration #1 — ristretto255-SHA512 OPRF, TripleDH key exchange,
//! Argon2id key-stretching function.

use opaque_ke::argon2::Argon2;
use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::{Ristretto255, ServerSetup, TripleDh};
use rand::rngs::OsRng;
use sha2::Sha512;

use crate::error::TesseraError;

/// The single Tessera OPAQUE cipher suite.
pub struct TesseraCipherSuite;

impl CipherSuite for TesseraCipherSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}

/// Serialized `ServerSetup` bytes — the server's long-term OPRF secret.
/// Generated once per deployment and provisioned to the sidecar (via Vault in prod).
pub type ServerSetupBytes = Vec<u8>;

/// Create a fresh server setup. Call once per deployment; persist the returned bytes.
pub fn new_server_setup() -> ServerSetupBytes {
    let mut rng = OsRng;
    let setup = ServerSetup::<TesseraCipherSuite>::new(&mut rng);
    setup.serialize().to_vec()
}

/// Serialize an in-memory `ServerSetup`.
pub fn serialize_server_setup(setup: &ServerSetup<TesseraCipherSuite>) -> ServerSetupBytes {
    setup.serialize().to_vec()
}

/// Load a `ServerSetup` from persisted bytes.
pub fn load_server_setup(bytes: &[u8]) -> Result<ServerSetup<TesseraCipherSuite>, TesseraError> {
    Ok(ServerSetup::<TesseraCipherSuite>::deserialize(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_setup_serializes_and_deserializes() {
        let bytes = new_server_setup();
        let parsed = load_server_setup(&bytes).expect("deserialize");
        // Re-serializing the parsed setup must reproduce the same bytes.
        assert_eq!(serialize_server_setup(&parsed), bytes);
    }
}
