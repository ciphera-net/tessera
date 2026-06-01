//! Tessera sidecar: serves OPAQUE server operations over a Unix domain socket.
//!
//! Usage:
//!   tessera-sidecar gen-setup <path>             write a fresh ServerSetup, then exit
//!   tessera-sidecar serve <socket> <setup-path>  run the socket server

use std::collections::HashMap;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::prelude::*;
use opaque_ke::ServerLogin;
use rand::RngCore;

use tessera::TesseraError;
use tessera::protocol::{Request, Response, read_frame, write_frame};
use tessera::server::{login_finish, login_start, register_finish, register_start};
use tessera::suite::{TesseraCipherSuite, load_server_setup, new_server_setup};

const LOGIN_TTL: Duration = Duration::from_secs(60);

type LoginMap = Arc<Mutex<HashMap<String, (ServerLogin<TesseraCipherSuite>, Instant)>>>;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("gen-setup") => {
            let path = args.get(2).expect("usage: gen-setup <path>");
            std::fs::write(path, new_server_setup()).expect("write setup");
            // Lock the OPRF secret to owner-read-only (0o400). This also guards against an
            // accidental re-run of `gen-setup` clobbering a live ServerSetup (overwriting it
            // would invalidate every existing credential): re-running now fails with EACCES
            // until the operator deliberately removes the file.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))
                    .expect("restrict setup file permissions");
            }
            eprintln!("wrote server setup to {path}");
        }
        Some("serve") => {
            let socket = args.get(2).expect("usage: serve <socket> <setup-path>");
            let setup_path = args.get(3).expect("usage: serve <socket> <setup-path>");
            serve(socket, setup_path);
        }
        _ => {
            eprintln!("usage: tessera-sidecar [gen-setup <path> | serve <socket> <setup-path>]");
            std::process::exit(2);
        }
    }
}

fn serve(socket_path: &str, setup_path: &str) {
    let setup_bytes = std::fs::read(setup_path).expect("read server setup");
    // Validate once at startup so a bad setup fails fast.
    load_server_setup(&setup_bytes).expect("server setup is valid");

    // Remove a stale socket file from a previous run.
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path).expect("bind unix socket");
    let logins: LoginMap = Arc::new(Mutex::new(HashMap::new()));

    eprintln!("tessera-sidecar listening on {socket_path}");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let setup_bytes = setup_bytes.clone();
                let logins = Arc::clone(&logins);
                std::thread::spawn(move || handle_conn(stream, &setup_bytes, logins));
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
}

fn handle_conn(mut stream: UnixStream, setup_bytes: &[u8], logins: LoginMap) {
    // One request per frame; loop until the peer closes.
    loop {
        let frame = match read_frame(&mut stream) {
            Ok(f) => f,
            Err(_) => return, // peer closed or bad frame
        };
        let resp = match serde_json::from_slice::<Request>(&frame) {
            Ok(req) => dispatch(req, setup_bytes, &logins).unwrap_or_else(|e| Response::Error {
                message: e.to_string(),
            }),
            Err(e) => Response::Error {
                message: format!("bad request json: {e}"),
            },
        };
        let bytes = serde_json::to_vec(&resp).expect("serialize response");
        if write_frame(&mut stream, &bytes).is_err() {
            return;
        }
    }
}

fn dispatch(req: Request, setup_bytes: &[u8], logins: &LoginMap) -> Result<Response, TesseraError> {
    let setup = load_server_setup(setup_bytes)?;
    match req {
        Request::RegisterStart {
            request_b64,
            credential_id,
        } => {
            let request = BASE64_STANDARD.decode(request_b64)?;
            let response = register_start(&setup, &request, credential_id.as_bytes())?;
            Ok(Response::RegisterStart {
                response_b64: BASE64_STANDARD.encode(response),
            })
        }
        Request::RegisterFinish { upload_b64 } => {
            let upload = BASE64_STANDARD.decode(upload_b64)?;
            let file = register_finish(&upload)?;
            Ok(Response::RegisterFinish {
                password_file_b64: BASE64_STANDARD.encode(file),
            })
        }
        Request::LoginStart {
            request_b64,
            password_file_b64,
            credential_id,
        } => {
            let request = BASE64_STANDARD.decode(request_b64)?;
            let file = match password_file_b64 {
                Some(b64) => Some(BASE64_STANDARD.decode(b64)?),
                None => None,
            };
            let (state, response) =
                login_start(&setup, file.as_deref(), &request, credential_id.as_bytes())?;
            let login_id = random_id();
            {
                let mut map = logins.lock().unwrap();
                prune_expired(&mut map);
                map.insert(login_id.clone(), (state, Instant::now()));
            }
            Ok(Response::LoginStart {
                login_id,
                response_b64: BASE64_STANDARD.encode(response),
            })
        }
        Request::LoginFinish {
            login_id,
            finalization_b64,
        } => {
            let finalization = BASE64_STANDARD.decode(finalization_b64)?;
            let (state, _) = {
                let mut map = logins.lock().unwrap();
                prune_expired(&mut map);
                map.remove(&login_id).ok_or(TesseraError::UnknownLogin)?
            };
            let session_key = login_finish(state, &finalization)?;
            Ok(Response::LoginFinish {
                session_key_b64: BASE64_STANDARD.encode(session_key),
            })
        }
    }
}

fn random_id() -> String {
    use std::fmt::Write as _;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn prune_expired(map: &mut HashMap<String, (ServerLogin<TesseraCipherSuite>, Instant)>) {
    let now = Instant::now();
    map.retain(|_, (_, started)| now.duration_since(*started) < LOGIN_TTL);
}
