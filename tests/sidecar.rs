//! End-to-end test: spawn the sidecar against a temp socket, run a full register + login
//! over the wire protocol, assert the server and client agree on the session key.

use std::os::unix::net::UnixStream;
use std::process::{Child, Command};
use std::time::Duration;

use base64::prelude::*;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use rand::rngs::OsRng;
use tessera::protocol::{Request, Response, read_frame, write_frame};
use tessera::suite::TesseraCipherSuite;

fn send(stream: &mut UnixStream, req: &Request) -> Response {
    let bytes = serde_json::to_vec(req).unwrap();
    write_frame(stream, &bytes).unwrap();
    let frame = read_frame(stream).unwrap();
    serde_json::from_slice(&frame).unwrap()
}

struct Sidecar(Child);
impl Drop for Sidecar {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn full_register_and_login_over_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("tessera.sock");
    let setup = dir.path().join("setup.bin");

    // gen-setup
    let status = Command::new(env!("CARGO_BIN_EXE_tessera-sidecar"))
        .args(["gen-setup", setup.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());

    // serve (held alive until _guard drops)
    let _guard = Sidecar(
        Command::new(env!("CARGO_BIN_EXE_tessera-sidecar"))
            .args(["serve", socket.to_str().unwrap(), setup.to_str().unwrap()])
            .spawn()
            .unwrap(),
    );

    // Wait for the socket to appear.
    let mut stream = None;
    for _ in 0..50 {
        if let Ok(s) = UnixStream::connect(&socket) {
            stream = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut stream = stream.expect("sidecar did not start");

    let password = b"correct horse battery staple";
    let creds = "creds-abc";
    let mut rng = OsRng;

    // ---- Registration ----
    let c_reg = ClientRegistration::<TesseraCipherSuite>::start(&mut rng, password).unwrap();
    let resp = send(&mut stream, &Request::RegisterStart {
        request_b64: BASE64_STANDARD.encode(c_reg.message.serialize()),
        credential_id: creds.into(),
    });
    let Response::RegisterStart { response_b64 } = resp else { panic!("expected RegisterStart, got {resp:?}") };
    let c_reg_finish = c_reg.state.finish(
        &mut rng,
        password,
        RegistrationResponse::deserialize(&BASE64_STANDARD.decode(response_b64).unwrap()).unwrap(),
        ClientRegistrationFinishParameters::default(),
    ).unwrap();
    let resp = send(&mut stream, &Request::RegisterFinish {
        upload_b64: BASE64_STANDARD.encode(c_reg_finish.message.serialize()),
    });
    let Response::RegisterFinish { password_file_b64 } = resp else { panic!("expected RegisterFinish, got {resp:?}") };

    // ---- Login ----
    let c_login = ClientLogin::<TesseraCipherSuite>::start(&mut rng, password).unwrap();
    let resp = send(&mut stream, &Request::LoginStart {
        request_b64: BASE64_STANDARD.encode(c_login.message.serialize()),
        password_file_b64: Some(password_file_b64),
        credential_id: creds.into(),
    });
    let Response::LoginStart { login_id, response_b64 } = resp else { panic!("expected LoginStart, got {resp:?}") };
    let c_login_finish = c_login.state.finish(
        &mut rng,
        password,
        CredentialResponse::deserialize(&BASE64_STANDARD.decode(response_b64).unwrap()).unwrap(),
        ClientLoginFinishParameters::default(),
    ).unwrap();
    let resp = send(&mut stream, &Request::LoginFinish {
        login_id,
        finalization_b64: BASE64_STANDARD.encode(c_login_finish.message.serialize()),
    });
    let Response::LoginFinish { session_key_b64 } = resp else { panic!("expected LoginFinish, got {resp:?}") };

    // Server and client must agree on the session key.
    assert_eq!(
        BASE64_STANDARD.decode(session_key_b64).unwrap(),
        c_login_finish.session_key.to_vec()
    );
}
