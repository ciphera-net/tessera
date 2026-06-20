//! Tessera sidecar: serves OPAQUE server operations over a Unix domain socket.
//!
//! Usage:
//!   tessera-sidecar gen-setup <path>             write a fresh ServerSetup, then exit
//!   tessera-sidecar serve <socket> <setup-path>  run the socket server

use std::collections::HashMap;
use std::io::{self, Read};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use base64::prelude::*;
use opaque_ke::{ServerLogin, ServerSetup};
use rand::RngCore;

use tessera::TesseraError;
use tessera::protocol::{MAX_FRAME, Request, Response, write_frame};
use tessera::server::{login_finish, login_start, register_finish, register_start};
use tessera::suite::{TesseraCipherSuite, load_server_setup, new_server_setup};

const DEFAULT_LOGIN_TTL: Duration = Duration::from_secs(60);
const DEFAULT_FRAME_DEADLINE: Duration = Duration::from_secs(10);
const DEFAULT_MAX_CONNECTIONS: usize = 256;

fn env_duration_ms(key: &str, default: Duration) -> Duration {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(default)
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(default)
}

/// Decrements the active-connection counter when a connection thread exits.
struct ConnGuard(Arc<AtomicUsize>);
impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

type LoginEntry = (ServerLogin<TesseraCipherSuite>, Instant);
type LoginMap = Arc<Mutex<HashMap<String, LoginEntry>>>;
type SharedSetup = Arc<ServerSetup<TesseraCipherSuite>>;

/// Lock the login map, recovering the guard if a previous holder panicked. The map is a cache
/// of independent in-flight `ServerLogin` states, so a poisoned lock does not imply corrupted
/// crypto state — recovering keeps the sidecar serving instead of cascading the panic.
fn lock_logins(logins: &LoginMap) -> MutexGuard<'_, HashMap<String, LoginEntry>> {
    logins
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

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
    let setup_bytes = match std::fs::read(setup_path) {
        Ok(b) => b,
        Err(e) => {
            match e.kind() {
                io::ErrorKind::PermissionDenied => eprintln!(
                    "FATAL: cannot read server setup at {setup_path}: permission denied. The container \
                     runs as nonroot (uid 65532); ensure the 0400 ServerSetup secret is owned by / \
                     readable by that uid."
                ),
                io::ErrorKind::NotFound => eprintln!(
                    "FATAL: server setup not found at {setup_path}. Did the Vault template render?"
                ),
                _ => eprintln!("FATAL: cannot read server setup at {setup_path}: {e}"),
            }
            std::process::exit(1);
        }
    };
    let setup: SharedSetup =
        Arc::new(load_server_setup(&setup_bytes).expect("server setup is valid"));
    drop(setup_bytes); // the parsed setup is the source of truth from here on

    let frame_deadline = env_duration_ms("TESSERA_FRAME_DEADLINE_MS", DEFAULT_FRAME_DEADLINE);
    let login_ttl = env_duration_ms("TESSERA_LOGIN_TTL_MS", DEFAULT_LOGIN_TTL);
    let max_conns = env_usize("TESSERA_MAX_CONNECTIONS", DEFAULT_MAX_CONNECTIONS);
    let active = Arc::new(AtomicUsize::new(0));

    // Remove a stale socket file from a previous run.
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path).expect("bind unix socket");
    // Restrict the socket to owner-only so that only the colocated process running as the same
    // uid can connect — defense in depth on top of the nonroot alloc-dir isolation.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
            .expect("restrict socket permissions");
    }
    let logins: LoginMap = Arc::new(Mutex::new(HashMap::new()));
    spawn_reaper(Arc::clone(&logins), login_ttl);

    eprintln!("tessera-sidecar listening on {socket_path}");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // Reserve a slot; refuse (close) past the cap.
                let prev = active.fetch_add(1, Ordering::SeqCst);
                if prev >= max_conns {
                    active.fetch_sub(1, Ordering::SeqCst);
                    eprintln!("connection refused: at capacity ({max_conns})");
                    drop(stream);
                    continue;
                }
                let guard = ConnGuard(Arc::clone(&active));
                let setup = Arc::clone(&setup);
                let logins = Arc::clone(&logins);
                std::thread::spawn(move || {
                    let _guard = guard; // decrements on thread exit
                    handle_conn(stream, &setup, logins, login_ttl, frame_deadline);
                });
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
}

/// Read one length-prefixed request frame with an idle-friendly, slow-loris-resistant policy:
/// the wait for the *first* byte of the next frame is unbounded (persistent pooled connections
/// may sit idle), but once a frame has started, the remainder must arrive within `frame_deadline`
/// or the connection is dropped. Returns `Ok(None)` on a clean idle close.
fn read_framed_request(
    stream: &mut UnixStream,
    frame_deadline: Duration,
) -> io::Result<Option<Vec<u8>>> {
    // Idle wait: block indefinitely for the first byte of the next frame.
    stream.set_read_timeout(None)?;
    let mut first = [0u8; 1];
    if stream.read(&mut first)? == 0 {
        return Ok(None); // peer closed cleanly between requests
    }
    // A frame has started — bound the time to receive the rest.
    stream.set_read_timeout(Some(frame_deadline))?;
    let mut rest = [0u8; 3];
    stream.read_exact(&mut rest)?;
    let len = u32::from_be_bytes([first[0], rest[0], rest[1], rest[2]]) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds MAX_FRAME",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    // Return to idle policy for the next frame.
    stream.set_read_timeout(None)?;
    Ok(Some(buf))
}

fn handle_conn(
    mut stream: UnixStream,
    setup: &ServerSetup<TesseraCipherSuite>,
    logins: LoginMap,
    ttl: Duration,
    frame_deadline: Duration,
) {
    loop {
        let frame = match read_framed_request(&mut stream, frame_deadline) {
            Ok(Some(f)) => f,
            Ok(None) => return, // clean idle close
            Err(_) => return,   // deadline exceeded, bad frame, or I/O error
        };
        let resp = match serde_json::from_slice::<Request>(&frame) {
            Ok(req) => dispatch(req, setup, &logins, ttl).unwrap_or_else(|e| Response::Error {
                code: e.code().to_string(),
                message: e.to_string(),
            }),
            Err(e) => Response::Error {
                code: "bad_request".to_string(),
                message: format!("bad request json: {e}"),
            },
        };
        // No-panic invariant: if a future Response variant ever fails to serialize, emit a fixed
        // internal-error frame instead of panicking the connection thread.
        let bytes = serde_json::to_vec(&resp).unwrap_or_else(|_| {
            br#"{"result":"error","code":"internal","message":"response serialization failed"}"#
                .to_vec()
        });
        if write_frame(&mut stream, &bytes).is_err() {
            return;
        }
    }
}

fn dispatch(
    req: Request,
    setup: &ServerSetup<TesseraCipherSuite>,
    logins: &LoginMap,
    ttl: Duration,
) -> Result<Response, TesseraError> {
    match req {
        Request::RegisterStart {
            request_b64,
            credential_id,
        } => {
            let request = BASE64_STANDARD.decode(request_b64)?;
            let response = register_start(setup, &request, credential_id.as_bytes())?;
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
                login_start(setup, file.as_deref(), &request, credential_id.as_bytes())?;
            let login_id = random_id();
            {
                let mut map = lock_logins(logins);
                prune_expired(&mut map, ttl);
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
                let mut map = lock_logins(logins);
                prune_expired(&mut map, ttl);
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

/// Background thread that prunes expired login state regardless of request traffic, keeping the
/// map bounded even when login traffic stops or the sidecar goes idle.
fn spawn_reaper(logins: LoginMap, ttl: Duration) {
    let interval = (ttl / 2).max(Duration::from_millis(50));
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(interval);
            let mut map = lock_logins(&logins);
            prune_expired(&mut map, ttl);
        }
    });
}

fn prune_expired(map: &mut HashMap<String, LoginEntry>, ttl: Duration) {
    let now = Instant::now();
    map.retain(|_, (_, started)| now.duration_since(*started) < ttl);
}

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_ke::ClientRegistration;
    use rand::rngs::OsRng;

    fn empty_logins() -> LoginMap {
        Arc::new(Mutex::new(HashMap::new()))
    }

    #[test]
    fn dispatch_register_start_uses_shared_setup() {
        let setup = load_server_setup(&new_server_setup()).unwrap();
        let logins = empty_logins();
        let mut rng = OsRng;
        let c = ClientRegistration::<TesseraCipherSuite>::start(&mut rng, b"pw").unwrap();
        let req = Request::RegisterStart {
            request_b64: BASE64_STANDARD.encode(c.message.serialize()),
            credential_id: "creds-1".into(),
        };
        // dispatch must accept a &ServerSetup that was parsed ONCE by the caller.
        let resp = dispatch(req, &setup, &logins, Duration::from_secs(60)).unwrap();
        assert!(matches!(resp, Response::RegisterStart { .. }));
    }

    #[test]
    fn poisoned_login_map_is_recovered() {
        let logins = empty_logins();
        let l2 = Arc::clone(&logins);
        // Poison the mutex by panicking while holding the guard.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = l2.lock().unwrap();
            panic!("poison the login map");
        }));
        // lock_logins must still hand back a usable guard.
        let mut g = lock_logins(&logins);
        g.clear();
        assert!(g.is_empty());
    }
}
