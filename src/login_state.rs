//! Sealed login state — lets the server finish an OPAQUE login on a different
//! process than the one that started it, without ever storing the state in
//! readable form.
//!
//! # Why this exists
//!
//! `ServerLogin` is the server's half of an in-flight OPAQUE key exchange. It
//! must survive between `login_start` and `login_finish`, which are two separate
//! requests. Holding it in process memory — as the sidecar did until this module
//! existed — makes those two requests inseparable from one process: a second
//! replica cannot finish a login the first one started, and a restart kills every
//! ceremony in flight.
//!
//! The obvious alternative, giving the sidecar a database client, is worse than
//! the problem. The sidecar deliberately has no network stack, no DB driver and a
//! read-only root filesystem; it is the process that holds the long-term OPRF
//! secret, and that isolation is its most valuable property. Adding a socket to
//! it to solve a scaling problem trades a security boundary for a convenience.
//!
//! So the state travels instead. `login_start` seals it, hands the ciphertext to
//! the caller, and forgets it. The caller — which already has a datastore, and
//! already stores a `login_id` there — stores the blob and passes it back at
//! `login_finish`. The datastore holds ciphertext it cannot open, and any process
//! holding the same `ServerSetup` can finish any login. The sidecar stays
//! stateless, network-free, and horizontally scalable.
//!
//! # Construction
//!
//! ```text
//! key        = HKDF-SHA512(ikm = ServerSetup bytes,
//!                          salt = "tessera-login-state-salt-v1",
//!                          info = "tessera:login-state:v1:xchacha20poly1305")
//! plaintext  = expires_at_ms (8 bytes, big-endian) || ServerLogin::serialize()
//! aad        = version byte || login_id
//! sealed     = version byte || nonce (24 bytes) || XChaCha20-Poly1305(key, nonce, plaintext, aad)
//! ```
//!
//! Design notes, each load-bearing:
//!
//! * **The key is derived, not stored.** Every process that can serve OPAQUE at
//!   all already holds the `ServerSetup`, so a derived key needs no new secret,
//!   no distribution channel and no separate rotation. HKDF is a PRF: the derived
//!   key reveals nothing about the OPRF secret it came from, and the `info`
//!   string keeps this key domain-separated from every other use of that seed.
//! * **XChaCha20-Poly1305, not AES-GCM.** Its 192-bit nonce makes random nonces
//!   safe without a counter, which a stateless sealer cannot keep anyway.
//! * **The expiry is inside the ciphertext, not beside it.** An attacker who
//!   could edit a plaintext TTL could keep a captured state alive; here the
//!   expiry is authenticated, so editing it fails the tag check.
//! * **The `login_id` is authenticated as AAD.** A blob sealed for one login
//!   cannot be replayed against another, even though both were sealed with the
//!   same key.
//! * **Failures are indistinguishable on purpose.** A forged blob, a blob for a
//!   different key, and an expired blob all return [`TesseraError::UnknownLogin`].
//!   Splitting them would hand an attacker an oracle for which of those it was,
//!   and the caller's correct response is identical in all three cases: this
//!   ceremony is dead, start a new one.
//!
//! Sealing does **not** by itself make a login single-use — replay is prevented
//! by the caller consuming its `login_id` binding exactly once (id-backend uses a
//! Redis `GETDEL`). The short expiry here bounds the damage if a caller forgets.

use std::time::Duration;

use base64::prelude::*;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use opaque_ke::ServerLogin;
use rand::RngCore;
use sha2::Sha512;
use zeroize::Zeroize;

use crate::error::TesseraError;
use crate::suite::TesseraCipherSuite;

/// Wire-format version. Bump only for an incompatible change to the layout
/// below; it is authenticated as AAD, so a downgrade attempt fails the tag check.
const SEAL_VERSION: u8 = 1;

const NONCE_LEN: usize = 24;
const EXPIRY_LEN: usize = 8;

const HKDF_SALT: &[u8] = b"tessera-login-state-salt-v1";
const HKDF_INFO: &[u8] = b"tessera:login-state:v1:xchacha20poly1305";

/// A sealing key derived from the `ServerSetup`. Derive it once at startup and
/// keep it; it zeroes itself on drop.
///
/// Holding this instead of the raw `ServerSetup` bytes is deliberate — the caller
/// can drop the setup bytes after deriving, so the long-term secret is not kept
/// in a second place just to seal short-lived state.
pub struct LoginStateKey([u8; 32]);

impl Drop for LoginStateKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl LoginStateKey {
    /// Derive the sealing key from serialized `ServerSetup` bytes.
    ///
    /// Every process given the same `ServerSetup` derives the same key, which is
    /// exactly what lets one replica finish another's login.
    pub fn derive(server_setup_bytes: &[u8]) -> Self {
        let hk = Hkdf::<Sha512>::new(Some(HKDF_SALT), server_setup_bytes);
        let mut okm = [0u8; 32];
        // Only fails for an absurd output length; 32 bytes is always valid.
        hk.expand(HKDF_INFO, &mut okm)
            .expect("HKDF expand of 32 bytes cannot fail");
        Self(okm)
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(Key::from_slice(&self.0))
    }
}

/// Additional authenticated data: the version and the login id this state belongs to.
fn aad(login_id: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + login_id.len());
    v.push(SEAL_VERSION);
    v.extend_from_slice(login_id.as_bytes());
    v
}

/// Seal an in-flight `ServerLogin` so it can be handed to an untrusted store and
/// returned later. `now_ms` is the current unix time in milliseconds; the state
/// becomes unopenable `ttl` after it.
pub fn seal(
    key: &LoginStateKey,
    login_id: &str,
    state: &ServerLogin<TesseraCipherSuite>,
    ttl: Duration,
    now_ms: u64,
) -> Result<String, TesseraError> {
    let expires_at_ms = now_ms.saturating_add(ttl.as_millis() as u64);

    let state_bytes = state.serialize();
    let mut plaintext = Vec::with_capacity(EXPIRY_LEN + state_bytes.len());
    plaintext.extend_from_slice(&expires_at_ms.to_be_bytes());
    plaintext.extend_from_slice(&state_bytes);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = key
        .cipher()
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext,
                aad: &aad(login_id),
            },
        )
        .map_err(|_| TesseraError::Internal("sealing login state failed".into()));

    // The plaintext holds the server's ephemeral KE state — zero it whether or
    // not sealing succeeded.
    plaintext.zeroize();
    let ciphertext = ciphertext?;

    let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    out.push(SEAL_VERSION);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(BASE64_STANDARD.encode(out))
}

/// Open a sealed `ServerLogin`. Returns [`TesseraError::UnknownLogin`] for
/// anything unusable — wrong key, tampered bytes, wrong `login_id`, or expired —
/// deliberately without distinguishing which.
pub fn open(
    key: &LoginStateKey,
    login_id: &str,
    sealed_b64: &str,
    now_ms: u64,
) -> Result<ServerLogin<TesseraCipherSuite>, TesseraError> {
    let raw = BASE64_STANDARD
        .decode(sealed_b64)
        .map_err(|_| TesseraError::UnknownLogin)?;

    if raw.len() <= 1 + NONCE_LEN {
        return Err(TesseraError::UnknownLogin);
    }
    if raw[0] != SEAL_VERSION {
        return Err(TesseraError::UnknownLogin);
    }

    let nonce = XNonce::from_slice(&raw[1..1 + NONCE_LEN]);
    let ciphertext = &raw[1 + NONCE_LEN..];

    let mut plaintext = key
        .cipher()
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &aad(login_id),
            },
        )
        .map_err(|_| TesseraError::UnknownLogin)?;

    let result = (|| {
        if plaintext.len() <= EXPIRY_LEN {
            return Err(TesseraError::UnknownLogin);
        }
        let mut expiry_bytes = [0u8; EXPIRY_LEN];
        expiry_bytes.copy_from_slice(&plaintext[..EXPIRY_LEN]);
        let expires_at_ms = u64::from_be_bytes(expiry_bytes);
        if now_ms >= expires_at_ms {
            return Err(TesseraError::UnknownLogin);
        }
        ServerLogin::<TesseraCipherSuite>::deserialize(&plaintext[EXPIRY_LEN..])
            .map_err(|_| TesseraError::UnknownLogin)
    })();

    plaintext.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{login_finish, login_start, register_finish, register_start};
    use crate::suite::{load_server_setup, new_server_setup};
    use opaque_ke::{
        ClientLogin, ClientLoginFinishParameters, ClientRegistration,
        ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
    };
    use rand::rngs::OsRng;

    const TTL: Duration = Duration::from_secs(60);
    const NOW: u64 = 1_700_000_000_000;

    fn setup_and_state() -> (Vec<u8>, ServerLogin<TesseraCipherSuite>, Vec<u8>, Vec<u8>) {
        let setup_bytes = new_server_setup();
        let setup = load_server_setup(&setup_bytes).unwrap();
        let mut rng = OsRng;

        let c_reg = ClientRegistration::<TesseraCipherSuite>::start(&mut rng, b"pw").unwrap();
        let reg_resp = register_start(&setup, &c_reg.message.serialize(), b"creds").unwrap();
        let c_reg_fin = c_reg
            .state
            .finish(
                &mut rng,
                b"pw",
                RegistrationResponse::deserialize(&reg_resp).unwrap(),
                ClientRegistrationFinishParameters::default(),
            )
            .unwrap();
        let file = register_finish(&c_reg_fin.message.serialize()).unwrap();

        let c_login = ClientLogin::<TesseraCipherSuite>::start(&mut rng, b"pw").unwrap();
        let (state, response) = login_start(
            &setup,
            Some(&file),
            &c_login.message.serialize(),
            b"creds",
        )
        .unwrap();

        // Drive the client to a finalization so tests can complete a real login.
        let c_fin = c_login
            .state
            .finish(
                &mut rng,
                b"pw",
                CredentialResponse::deserialize(&response).unwrap(),
                ClientLoginFinishParameters::default(),
            )
            .unwrap();
        (
            setup_bytes,
            state,
            c_fin.message.serialize().to_vec(),
            c_fin.session_key.to_vec(),
        )
    }

    /// The property the whole design rests on: a login sealed by one process is
    /// finishable by a DIFFERENT process that only shares the ServerSetup, and
    /// the session keys still agree.
    #[test]
    fn sealed_state_finishes_on_a_different_process() {
        let (setup_bytes, state, finalization, client_session_key) = setup_and_state();

        // "Process A" seals and forgets.
        let key_a = LoginStateKey::derive(&setup_bytes);
        let sealed = seal(&key_a, "login-1", &state, TTL, NOW).unwrap();
        drop(state);
        drop(key_a);

        // "Process B" derives the same key from the same setup and finishes.
        let key_b = LoginStateKey::derive(&setup_bytes);
        let reopened = open(&key_b, "login-1", &sealed, NOW + 1_000).unwrap();
        let server_session_key = login_finish(reopened, &finalization).unwrap();

        assert_eq!(
            server_session_key, client_session_key,
            "a login finished from sealed state must derive the same session key"
        );
    }

    #[test]
    fn sealed_state_is_not_readable_without_the_key() {
        let (setup_bytes, state, _, _) = setup_and_state();
        let key = LoginStateKey::derive(&setup_bytes);
        let sealed = seal(&key, "login-1", &state, TTL, NOW).unwrap();

        let raw = BASE64_STANDARD.decode(&sealed).unwrap();
        let state_bytes = state.serialize();
        assert!(
            !raw.windows(state_bytes.len()).any(|w| w == &state_bytes[..]),
            "the serialized ServerLogin must not appear in the sealed output"
        );
    }

    #[test]
    fn a_different_server_setup_cannot_open_it() {
        let (setup_bytes, state, _, _) = setup_and_state();
        let sealed = seal(&LoginStateKey::derive(&setup_bytes), "login-1", &state, TTL, NOW).unwrap();

        let other = LoginStateKey::derive(&new_server_setup());
        assert!(matches!(
            open(&other, "login-1", &sealed, NOW),
            Err(TesseraError::UnknownLogin)
        ));
    }

    /// Without AAD binding, a captured blob could be replayed under another
    /// login_id — the caller would resolve a different user's binding and finish
    /// a ceremony that user never started.
    #[test]
    fn state_cannot_be_replayed_under_a_different_login_id() {
        let (setup_bytes, state, _, _) = setup_and_state();
        let key = LoginStateKey::derive(&setup_bytes);
        let sealed = seal(&key, "login-1", &state, TTL, NOW).unwrap();

        assert!(matches!(
            open(&key, "login-2", &sealed, NOW),
            Err(TesseraError::UnknownLogin)
        ));
    }

    #[test]
    fn expired_state_is_rejected() {
        let (setup_bytes, state, _, _) = setup_and_state();
        let key = LoginStateKey::derive(&setup_bytes);
        let sealed = seal(&key, "login-1", &state, TTL, NOW).unwrap();

        assert!(open(&key, "login-1", &sealed, NOW + TTL.as_millis() as u64).is_err());
        assert!(open(&key, "login-1", &sealed, NOW + TTL.as_millis() as u64 + 1).is_err());
        // Still valid one millisecond before expiry.
        assert!(open(&key, "login-1", &sealed, NOW + TTL.as_millis() as u64 - 1).is_ok());
    }

    /// Every byte matters: flipping any one of them must fail the tag check.
    #[test]
    fn tampered_state_is_rejected() {
        let (setup_bytes, state, _, _) = setup_and_state();
        let key = LoginStateKey::derive(&setup_bytes);
        let sealed = seal(&key, "login-1", &state, TTL, NOW).unwrap();
        let raw = BASE64_STANDARD.decode(&sealed).unwrap();

        for i in 0..raw.len() {
            let mut bad = raw.clone();
            bad[i] ^= 0x01;
            let bad_b64 = BASE64_STANDARD.encode(&bad);
            assert!(
                open(&key, "login-1", &bad_b64, NOW).is_err(),
                "flipping byte {i} must invalidate the sealed state"
            );
        }
    }

    #[test]
    fn malformed_input_is_rejected_without_panicking() {
        let key = LoginStateKey::derive(&new_server_setup());
        for bad in ["", "!!!not base64!!!", "AAAA", &BASE64_STANDARD.encode([2u8; 40])] {
            assert!(matches!(
                open(&key, "login-1", bad, NOW),
                Err(TesseraError::UnknownLogin)
            ));
        }
    }

    #[test]
    fn derivation_is_deterministic_and_setup_specific() {
        let a = new_server_setup();
        let b = new_server_setup();
        assert_eq!(
            LoginStateKey::derive(&a).0,
            LoginStateKey::derive(&a).0,
            "same setup must derive the same key, or replicas cannot share state"
        );
        assert_ne!(
            LoginStateKey::derive(&a).0,
            LoginStateKey::derive(&b).0,
            "different setups must derive different keys"
        );
    }

    /// The sealing key must not be the setup itself, or a leak of one is a leak
    /// of the other.
    #[test]
    fn derived_key_does_not_appear_in_the_setup_bytes() {
        let setup_bytes = new_server_setup();
        let key = LoginStateKey::derive(&setup_bytes);
        assert!(
            !setup_bytes.windows(32).any(|w| w == key.0),
            "derived key must not be a substring of the ServerSetup"
        );
    }
}
