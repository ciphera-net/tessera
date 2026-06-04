//! Stateless server-side OPAQUE wrappers over `opaque-ke`.
//!
//! These functions are pure (no I/O, no persistent state). The sidecar binary holds
//! the short-lived `ServerLogin` value between `login_start` and `login_finish`.

use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use zeroize::Zeroize;

use crate::error::TesseraError;
use crate::suite::TesseraCipherSuite;

/// Process the client's registration request. `credential_identifier` is the stable
/// per-account lookup key (the blind index, supplied by the Go SDK in Phase 2).
/// Returns the serialized `RegistrationResponse` to send back to the client.
pub fn register_start(
    server_setup: &ServerSetup<TesseraCipherSuite>,
    registration_request: &[u8],
    credential_identifier: &[u8],
) -> Result<Vec<u8>, TesseraError> {
    let request = RegistrationRequest::<TesseraCipherSuite>::deserialize(registration_request)?;
    let result = ServerRegistration::start(server_setup, request, credential_identifier)?;
    Ok(result.message.serialize().to_vec())
}

/// Finalize registration. Returns the serialized password file the caller must persist
/// for this account (it is the input to every future `login_start`).
pub fn register_finish(registration_upload: &[u8]) -> Result<Vec<u8>, TesseraError> {
    let upload = RegistrationUpload::<TesseraCipherSuite>::deserialize(registration_upload)?;
    let password_file = ServerRegistration::<TesseraCipherSuite>::finish(upload);
    Ok(password_file.serialize().to_vec())
}

/// Begin authentication. `password_file` is the stored registration record, or `None`
/// to force a timing-safe dummy response for unknown accounts. Returns the in-memory
/// `ServerLogin` state (keep until `login_finish`) and the serialized `CredentialResponse`.
pub fn login_start(
    server_setup: &ServerSetup<TesseraCipherSuite>,
    password_file: Option<&[u8]>,
    credential_request: &[u8],
    credential_identifier: &[u8],
) -> Result<(ServerLogin<TesseraCipherSuite>, Vec<u8>), TesseraError> {
    let mut rng = rand::rngs::OsRng;
    let record = match password_file {
        Some(bytes) => Some(ServerRegistration::<TesseraCipherSuite>::deserialize(
            bytes,
        )?),
        None => None,
    };
    let request = CredentialRequest::<TesseraCipherSuite>::deserialize(credential_request)?;
    let result = ServerLogin::start(
        &mut rng,
        server_setup,
        record,
        request,
        credential_identifier,
        ServerLoginParameters::default(),
    )?;
    Ok((result.state, result.message.serialize().to_vec()))
}

/// Finalize authentication. Returns the server's copy of the session key (must equal the
/// client's). A returned `Ok` means the client proved knowledge of the password.
pub fn login_finish(
    server_login: ServerLogin<TesseraCipherSuite>,
    credential_finalization: &[u8],
) -> Result<Vec<u8>, TesseraError> {
    let finalization =
        CredentialFinalization::<TesseraCipherSuite>::deserialize(credential_finalization)?;
    let mut result = server_login.finish(finalization, ServerLoginParameters::default())?;
    let sk = result.session_key.to_vec();
    // opaque-ke 4.x ServerLoginFinishResult is NOT ZeroizeOnDrop — zero the session_key copy it holds.
    result.session_key.as_mut_slice().zeroize();
    Ok(sk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::{load_server_setup, new_server_setup};
    use opaque_ke::{
        ClientLogin, ClientLoginFinishParameters, ClientRegistration,
        ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
    };
    use rand::rngs::OsRng;

    /// Helper: run a full client+server registration, returning the stored password file
    /// and the client's export_key (the vault key material).
    fn register(
        setup: &ServerSetup<TesseraCipherSuite>,
        password: &[u8],
        creds: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let mut rng = OsRng;
        let c_start = ClientRegistration::<TesseraCipherSuite>::start(&mut rng, password).unwrap();
        let resp = register_start(setup, &c_start.message.serialize(), creds).unwrap();
        let c_finish = c_start
            .state
            .finish(
                &mut rng,
                password,
                RegistrationResponse::deserialize(&resp).unwrap(),
                ClientRegistrationFinishParameters::default(),
            )
            .unwrap();
        let file = register_finish(&c_finish.message.serialize()).unwrap();
        (file, c_finish.export_key.to_vec())
    }

    #[test]
    fn registration_produces_loadable_password_file() {
        let setup = load_server_setup(&new_server_setup()).unwrap();
        let (file, _export_key) = register(&setup, b"correct horse", b"creds-123");
        assert!(!file.is_empty());
        ServerRegistration::<TesseraCipherSuite>::deserialize(&file).unwrap();
    }

    #[test]
    fn login_round_trip_agrees_on_keys() {
        let setup = load_server_setup(&new_server_setup()).unwrap();
        let (file, reg_export_key) = register(&setup, b"correct horse", b"creds-123");
        let mut rng = OsRng;

        let c_start = ClientLogin::<TesseraCipherSuite>::start(&mut rng, b"correct horse").unwrap();
        let (server_state, resp) = login_start(
            &setup,
            Some(&file),
            &c_start.message.serialize(),
            b"creds-123",
        )
        .unwrap();
        let c_finish = c_start
            .state
            .finish(
                &mut rng,
                b"correct horse",
                CredentialResponse::deserialize(&resp).unwrap(),
                ClientLoginFinishParameters::default(),
            )
            .unwrap();
        let server_session_key = login_finish(server_state, &c_finish.message.serialize()).unwrap();

        // Both sides must derive the same session key.
        assert_eq!(c_finish.session_key.to_vec(), server_session_key);
        // export_key from login must equal export_key from registration (the vault key).
        assert_eq!(c_finish.export_key.to_vec(), reg_export_key);
    }

    #[test]
    fn login_with_wrong_password_is_rejected() {
        let setup = load_server_setup(&new_server_setup()).unwrap();
        let (file, _) = register(&setup, b"correct horse", b"creds-123");
        let mut rng = OsRng;

        let c_start =
            ClientLogin::<TesseraCipherSuite>::start(&mut rng, b"WRONG password").unwrap();
        let (_server_state, resp) = login_start(
            &setup,
            Some(&file),
            &c_start.message.serialize(),
            b"creds-123",
        )
        .unwrap();
        let result = c_start.state.finish(
            &mut rng,
            b"WRONG password",
            CredentialResponse::deserialize(&resp).unwrap(),
            ClientLoginFinishParameters::default(),
        );
        assert!(result.is_err(), "wrong password must fail at client finish");
    }

    #[test]
    fn login_start_with_unknown_user_returns_ok() {
        // `None` must reach `ServerLogin::start` so opaque-ke produces a timing-safe dummy
        // response. An `Err` here would mean the wrapper short-circuits on unknown accounts,
        // leaking their (non-)existence via an error/timing signal.
        let setup = load_server_setup(&new_server_setup()).unwrap();
        let mut rng = OsRng;
        let c_start = ClientLogin::<TesseraCipherSuite>::start(&mut rng, b"any password").unwrap();
        let result = login_start(
            &setup,
            None,
            &c_start.message.serialize(),
            b"nonexistent-user",
        );
        assert!(
            result.is_ok(),
            "unknown user must yield a dummy response, not an error"
        );
    }
}
