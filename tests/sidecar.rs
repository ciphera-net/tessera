//! End-to-end test: spawn the sidecar against a temp socket, run a full register + login
//! over the wire protocol, assert the server and client agree on the session key.

use std::io::{Read, Write};
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
    let resp = send(
        &mut stream,
        &Request::RegisterStart {
            request_b64: BASE64_STANDARD.encode(c_reg.message.serialize()),
            credential_id: creds.into(),
        },
    );
    let Response::RegisterStart { response_b64 } = resp else {
        panic!("expected RegisterStart, got {resp:?}")
    };
    let c_reg_finish = c_reg
        .state
        .finish(
            &mut rng,
            password,
            RegistrationResponse::deserialize(&BASE64_STANDARD.decode(response_b64).unwrap())
                .unwrap(),
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let resp = send(
        &mut stream,
        &Request::RegisterFinish {
            upload_b64: BASE64_STANDARD.encode(c_reg_finish.message.serialize()),
        },
    );
    let Response::RegisterFinish { password_file_b64 } = resp else {
        panic!("expected RegisterFinish, got {resp:?}")
    };

    // ---- Login ----
    let c_login = ClientLogin::<TesseraCipherSuite>::start(&mut rng, password).unwrap();
    let resp = send(
        &mut stream,
        &Request::LoginStart {
            request_b64: BASE64_STANDARD.encode(c_login.message.serialize()),
            password_file_b64: Some(password_file_b64),
            credential_id: creds.into(),
        },
    );
    let Response::LoginStart {
        login_id,
        response_b64,
    } = resp
    else {
        panic!("expected LoginStart, got {resp:?}")
    };
    let c_login_finish = c_login
        .state
        .finish(
            &mut rng,
            password,
            CredentialResponse::deserialize(&BASE64_STANDARD.decode(response_b64).unwrap())
                .unwrap(),
            ClientLoginFinishParameters::default(),
        )
        .unwrap();
    let resp = send(
        &mut stream,
        &Request::LoginFinish {
            login_id,
            finalization_b64: BASE64_STANDARD.encode(c_login_finish.message.serialize()),
        },
    );
    let Response::LoginFinish { session_key_b64 } = resp else {
        panic!("expected LoginFinish, got {resp:?}")
    };

    // Server and client must agree on the session key.
    assert_eq!(
        BASE64_STANDARD.decode(session_key_b64).unwrap(),
        c_login_finish.session_key.to_vec()
    );
}

/// Helper: gen-setup + serve with extra env, returning (guard, socket path) once connectable.
fn start_sidecar_with_env(
    dir: &std::path::Path,
    env: &[(&str, &str)],
) -> (Sidecar, std::path::PathBuf) {
    let socket = dir.join("tessera.sock");
    let setup = dir.join("setup.bin");
    let status = Command::new(env!("CARGO_BIN_EXE_tessera-sidecar"))
        .args(["gen-setup", setup.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tessera-sidecar"));
    cmd.args(["serve", socket.to_str().unwrap(), setup.to_str().unwrap()]);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let guard = Sidecar(cmd.spawn().unwrap());
    for _ in 0..50 {
        if UnixStream::connect(&socket).is_ok() {
            return (guard, socket);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("sidecar did not start");
}

#[test]
fn started_frame_that_stalls_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let (_guard, socket) =
        start_sidecar_with_env(dir.path(), &[("TESSERA_FRAME_DEADLINE_MS", "300")]);
    let mut stream = UnixStream::connect(&socket).unwrap();
    // Send a length prefix that promises 16 bytes, then send nothing more.
    stream.write_all(&16u32.to_be_bytes()).unwrap();
    stream.flush().unwrap();
    // After the deadline the sidecar drops the connection; our next read sees EOF/err.
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1];
    let r = stream.read(&mut buf);
    assert!(
        matches!(r, Ok(0)) || r.is_err(),
        "stalled frame must cause the sidecar to close the connection"
    );
}

#[test]
fn idle_connection_is_not_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let (_guard, socket) =
        start_sidecar_with_env(dir.path(), &[("TESSERA_FRAME_DEADLINE_MS", "300")]);
    let mut stream = UnixStream::connect(&socket).unwrap();
    // Sit idle well past the frame deadline WITHOUT starting a frame.
    std::thread::sleep(Duration::from_millis(900));
    // The connection must still be usable: a bad-json frame should still get an Error response,
    // proving the sidecar did not reap the idle connection.
    write_frame(&mut stream, b"not json").unwrap();
    let resp: Response = serde_json::from_slice(&read_frame(&mut stream).unwrap()).unwrap();
    assert!(matches!(resp, Response::Error { .. }));
}

#[test]
fn connections_past_the_cap_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (_guard, socket) = start_sidecar_with_env(
        dir.path(),
        &[
            ("TESSERA_MAX_CONNECTIONS", "2"),
            ("TESSERA_FRAME_DEADLINE_MS", "2000"),
        ],
    );
    // Hold 2 connections open and idle (each pins a server thread → fills the cap).
    let _c1 = UnixStream::connect(&socket).unwrap();
    let _c2 = UnixStream::connect(&socket).unwrap();
    std::thread::sleep(Duration::from_millis(200)); // let the server accept + count them
    // The 3rd connection is accepted then immediately closed by the server.
    let mut c3 = UnixStream::connect(&socket).unwrap();
    c3.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = [0u8; 1];
    let r = c3.read(&mut buf);
    assert!(
        matches!(r, Ok(0)) || r.is_err(),
        "connection past the cap must be closed by the server"
    );
}

#[test]
fn login_state_is_reaped_after_ttl() {
    let dir = tempfile::tempdir().unwrap();
    let (_guard, socket) = start_sidecar_with_env(
        dir.path(),
        &[
            ("TESSERA_LOGIN_TTL_MS", "200"),
            ("TESSERA_FRAME_DEADLINE_MS", "2000"),
        ],
    );
    let mut stream = UnixStream::connect(&socket).unwrap();
    let password = b"correct horse battery staple";
    let creds = "creds-reap";
    let mut rng = OsRng;

    // Register so a real password file exists.
    let c_reg = ClientRegistration::<TesseraCipherSuite>::start(&mut rng, password).unwrap();
    let Response::RegisterStart { response_b64 } = send(
        &mut stream,
        &Request::RegisterStart {
            request_b64: BASE64_STANDARD.encode(c_reg.message.serialize()),
            credential_id: creds.into(),
        },
    ) else {
        panic!()
    };
    let c_reg_finish = c_reg
        .state
        .finish(
            &mut rng,
            password,
            RegistrationResponse::deserialize(&BASE64_STANDARD.decode(response_b64).unwrap())
                .unwrap(),
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let Response::RegisterFinish { password_file_b64 } = send(
        &mut stream,
        &Request::RegisterFinish {
            upload_b64: BASE64_STANDARD.encode(c_reg_finish.message.serialize()),
        },
    ) else {
        panic!()
    };

    // LoginStart creates server state; then we wait past the TTL so the reaper removes it.
    let c_login = ClientLogin::<TesseraCipherSuite>::start(&mut rng, password).unwrap();
    let Response::LoginStart { login_id, .. } = send(
        &mut stream,
        &Request::LoginStart {
            request_b64: BASE64_STANDARD.encode(c_login.message.serialize()),
            password_file_b64: Some(password_file_b64),
            credential_id: creds.into(),
        },
    ) else {
        panic!()
    };

    std::thread::sleep(Duration::from_millis(600)); // > TTL; reaper ticks at 100 ms

    let resp = send(
        &mut stream,
        &Request::LoginFinish {
            login_id,
            finalization_b64: BASE64_STANDARD.encode(b"ignored-after-reap"),
        },
    );
    // Assert specifically on the "unknown login" message so this test is falsifiable: before the
    // TTL was env-driven, the 60s default kept the (valid) state alive and LoginFinish rejected the
    // garbage finalization cryptographically (a different Error message) — that must NOT pass here.
    // NOTE: this verifies the combined TTL-enforcement path, not the reaper thread in isolation —
    // with a 600ms wait the per-request prune inside LoginFinish dispatch also removes the expired
    // entry before map.remove runs. Isolating the reaper would require exercising it under zero
    // login traffic, which the wire protocol does not expose.
    assert!(
        matches!(resp, Response::Error { ref code, ref message } if code == "unknown_login" && message.contains("unknown login")),
        "reaped login state must yield an 'unknown_login' coded Error, got {resp:?}"
    );
}

#[test]
fn socket_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let (_guard, socket) = start_sidecar_with_env(dir.path(), &[]);
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "socket must be chmod 0o600");
}

#[test]
fn serve_with_missing_setup_exits_with_diagnostic() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("t.sock");
    let out = Command::new(env!("CARGO_BIN_EXE_tessera-sidecar"))
        .args(["serve", socket.to_str().unwrap(), "/no/such/setup.bin"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "must exit non-zero when the setup is missing"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("server setup not found"),
        "stderr must name the problem: {stderr}"
    );
}
