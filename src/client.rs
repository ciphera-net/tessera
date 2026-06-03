//! Client-side OPAQUE steps — the browser/WASM half, mirroring `server.rs`. First-class (not an
//! example) so `examples/client_helper.rs` and the `tessera-wasm` bindings compile from ONE source,
//! making browser↔sidecar parity hold by construction. The KSF parameters are pinned HERE and are a
//! cross-language parity contract: they are baked into the registration envelope and MUST be
//! reproduced byte-identically at every login.

use opaque_ke::argon2::{Algorithm, Argon2, Params, Version};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
};
use rand::rngs::OsRng;

use crate::error::TesseraError;
use crate::suite::TesseraCipherSuite;

/// Client-held OPAQUE state between start and finish. Aliased so downstream crates (tessera-wasm)
/// can name it WITHOUT a direct opaque-ke dependency — avoiding cross-crate feature-matching on the
/// suite. opaque-ke's state types zeroize their secret material on drop.
pub type RegistrationState = ClientRegistration<TesseraCipherSuite>;
pub type LoginState = ClientLogin<TesseraCipherSuite>;

/// Login's three outputs: `(serialized CredentialFinalization, session_key, export_key)`. Aliased so
/// the `login_finish` signature stays within clippy's type-complexity budget and to name the tuple's
/// meaning at call sites (the `tessera-wasm` `LoginFinish` binding destructures it positionally).
pub type LoginFinishOutput = (Vec<u8>, Vec<u8>, Vec<u8>);

/// The pinned client-side OPAQUE KSF: Argon2id, version 0x13, m=64 MiB, t=3, p=1.
///
/// PINNED EXPLICITLY rather than inheriting opaque-ke's default (with `ksf: None`, opaque-ke would
/// use `<CS::Ksf as Default>::default()` = `Argon2::default()`, i.e. the argon2 crate's ~19 MiB/t=2
/// defaults). Pinning removes any dependence on that default and on its stability across versions.
///
/// `output_len` MUST be `None` here. opaque-ke's `Ksf::hash` impl (ksf.rs) allocates a pre-sized
/// 64-byte `GenericArray` (the Sha512 OPRF hash size) and passes it to `hash_password_into`; with
/// `output_len = None` argon2 imposes no size constraint and accepts the 64-byte buffer. Setting
/// `Some(32)` here would make argon2 reject the 64-byte buffer with `Error::OutputTooLong`, which
/// opaque-ke maps via `.map_err(|_| InternalError::KsfError)?` and surfaces as
/// `TesseraError::Opaque(ProtocolError::LibraryError(..))` — i.e. `register_finish` would FAIL
/// (return `Err`, not panic) and envelope recovery would be impossible. (Contrast `blind_index`,
/// which DOES set `Some(32)` because it passes a fixed `[0u8; 32]` buffer.)
///
/// p=1 is mandatory: browser/WASM Argon2 is single-lane (see the blind-index parity note).
fn tessera_opaque_ksf() -> Argon2<'static> {
    let params = Params::new(65_536, 3, 1, None).expect("static OPAQUE KSF params are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Begin registration. Returns `(serialized RegistrationRequest, client state)`. The state holds the
/// password blinding scalar and must be supplied (with the same password) to `register_finish`.
pub fn register_start(password: &[u8]) -> Result<(Vec<u8>, RegistrationState), TesseraError> {
    let mut rng = OsRng;
    let result = ClientRegistration::<TesseraCipherSuite>::start(&mut rng, password)?;
    Ok((result.message.serialize().to_vec(), result.state))
}

/// Finalize registration. Returns `(serialized RegistrationUpload, export_key)`. `export_key` is the
/// 64-byte CLIENT-ONLY vault key material — it MUST NEVER cross the wire.
pub fn register_finish(
    state: RegistrationState,
    password: &[u8],
    registration_response: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), TesseraError> {
    let mut rng = OsRng;
    let response = RegistrationResponse::<TesseraCipherSuite>::deserialize(registration_response)?;
    let ksf = tessera_opaque_ksf();
    let params = ClientRegistrationFinishParameters::new(Identifiers::default(), Some(&ksf));
    let result = state.finish(&mut rng, password, response, params)?;
    Ok((
        result.message.serialize().to_vec(),
        result.export_key.to_vec(),
    ))
}

/// Begin login. Returns `(serialized CredentialRequest, client state)`.
pub fn login_start(password: &[u8]) -> Result<(Vec<u8>, LoginState), TesseraError> {
    let mut rng = OsRng;
    let result = ClientLogin::<TesseraCipherSuite>::start(&mut rng, password)?;
    Ok((result.message.serialize().to_vec(), result.state))
}

/// Finalize login. Returns `(serialized CredentialFinalization, session_key, export_key)`. A returned
/// `Ok` means the server proved knowledge of the password too (mutual auth via the TripleDh
/// server-key MAC). `export_key` equals the value from registration and MUST NEVER cross the wire.
pub fn login_finish(
    state: LoginState,
    password: &[u8],
    credential_response: &[u8],
) -> Result<LoginFinishOutput, TesseraError> {
    let mut rng = OsRng;
    let response = CredentialResponse::<TesseraCipherSuite>::deserialize(credential_response)?;
    // The KSF MUST be supplied at login too (it is NOT auto-applied from the credential response):
    // OPAQUE re-stretches the OPRF output with the KSF here to recover the envelope, so login MUST
    // use the SAME params as registration. Do NOT "simplify" this to ClientLoginFinishParameters
    // ::default() — that would apply Argon2::default() (~19 MiB/t=2) ≠ registration's 64 MiB/t=3 and
    // envelope recovery would FAIL (login error / wrong export_key). opaque-ke 4.0.1 confirms the
    // `ksf` field exists on this struct precisely because the client owns the KSF at login.
    let ksf = tessera_opaque_ksf();
    let params = ClientLoginFinishParameters::new(None, Identifiers::default(), Some(&ksf));
    let result = state.finish(&mut rng, password, response, params)?;
    Ok((
        result.message.serialize().to_vec(),
        result.session_key.to_vec(),
        result.export_key.to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server;
    use crate::suite::{load_server_setup, new_server_setup};

    #[test]
    fn full_round_trip_agrees_and_export_key_is_stable() {
        let setup = load_server_setup(&new_server_setup()).unwrap();
        let creds = b"creds-123";
        let password = b"correct horse";

        // Registration
        let (reg_req, reg_state) = register_start(password).unwrap();
        let reg_resp = server::register_start(&setup, &reg_req, creds).unwrap();
        let (upload, reg_export_key) = register_finish(reg_state, password, &reg_resp).unwrap();
        let password_file = server::register_finish(&upload).unwrap();

        // Login
        let (login_req, login_state) = login_start(password).unwrap();
        let (server_state, cred_resp) =
            server::login_start(&setup, Some(&password_file), &login_req, creds).unwrap();
        let (finalization, client_session_key, login_export_key) =
            login_finish(login_state, password, &cred_resp).unwrap();
        let server_session_key = server::login_finish(server_state, &finalization).unwrap();

        assert_eq!(
            client_session_key, server_session_key,
            "session keys must agree"
        );
        assert_eq!(
            reg_export_key, login_export_key,
            "export_key must be stable"
        );
        assert_eq!(reg_export_key.len(), 64, "export_key is 64 bytes");
        assert_eq!(client_session_key.len(), 64, "session_key is 64 bytes");
    }

    #[test]
    fn wrong_password_fails_at_login_finish() {
        let setup = load_server_setup(&new_server_setup()).unwrap();
        let (reg_req, reg_state) = register_start(b"right").unwrap();
        let reg_resp = server::register_start(&setup, &reg_req, b"c").unwrap();
        let (upload, _) = register_finish(reg_state, b"right", &reg_resp).unwrap();
        let pf = server::register_finish(&upload).unwrap();
        let (login_req, login_state) = login_start(b"wrong").unwrap();
        let (_s, cred_resp) = server::login_start(&setup, Some(&pf), &login_req, b"c").unwrap();
        assert!(login_finish(login_state, b"wrong", &cred_resp).is_err());
    }
}
