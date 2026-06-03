//! OPAQUE client-side test helper (dev/CI only — an examples/ target, never shipped in the
//! sidecar image). Drives the client steps via a line protocol on stdin/stdout so an integration
//! test in another language can relay messages to a real `tessera-sidecar`.
//!
//! The crypto is delegated to `tessera::client` — the SAME first-class code path the `tessera-wasm`
//! browser bindings compile from — so this helper now exercises the PRODUCTION pinned KSF
//! (Argon2id/64 MiB/t=3), not opaque-ke's default. That makes the cross-language integration test a
//! real check on the pinned KSF's interop.
//!
//! WARNING: this helper prints export_key on stdout (reg-finish / login-finish replies), so it
//! WILL appear in CI logs under `go test -v`. Safe ONLY with ephemeral test credentials (a fresh
//! `gen-setup` ServerSetup + a throw-away password). NEVER run it against a production ServerSetup
//! or a real user password. Arguments are whitespace-delimited, so the password must be a single
//! token (no spaces).
//!
//! Commands (one per stdin line; base64 args; replies on stdout):
//!   reg-start    <password>                     -> OK <registration_request_b64>
//!   reg-finish   <password> <reg_response_b64>  -> OK <registration_upload_b64> <export_key_b64>
//!   login-start  <password>                     -> OK <credential_request_b64>
//!   login-finish <password> <cred_response_b64> -> OK <finalization_b64> <session_key_b64> <export_key_b64>
//! On error: "ERR <message>".

use std::io::{BufRead, Write};

use base64::prelude::*;
use tessera::client::{self, LoginState, RegistrationState};

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    let mut reg_state: Option<RegistrationState> = None;
    let mut login_state: Option<LoginState> = None;

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                // Surface the read failure to stderr (the Go harness wires it to os.Stderr) rather
                // than exiting silently, which would look like an empty reply to the test driver.
                eprintln!("client_helper: stdin read error: {e}");
                break;
            }
        };
        let parts: Vec<&str> = line.split_whitespace().collect();
        let reply = handle(&parts, &mut reg_state, &mut login_state);
        writeln!(out, "{reply}").expect("write stdout");
        out.flush().expect("flush stdout");
    }
}

fn b64d(s: &str) -> Result<Vec<u8>, String> {
    BASE64_STANDARD
        .decode(s)
        .map_err(|e| format!("base64: {e}"))
}

fn handle(
    parts: &[&str],
    reg_state: &mut Option<RegistrationState>,
    login_state: &mut Option<LoginState>,
) -> String {
    match parts {
        ["reg-start", password] => match client::register_start(password.as_bytes()) {
            Ok((request, state)) => {
                *reg_state = Some(state);
                format!("OK {}", BASE64_STANDARD.encode(request))
            }
            Err(e) => format!("ERR {e:?}"),
        },
        ["reg-finish", password, resp_b64] => {
            // Decode base64 BEFORE consuming the stored state so a raw decode error is reported
            // without advancing state. A valid-base64 but malformed OPAQUE response is caught
            // INSIDE client::register_finish (state already taken) — fine for a single-shot helper.
            let resp_bytes = match b64d(resp_b64) {
                Ok(b) => b,
                Err(e) => return format!("ERR {e}"),
            };
            let state = match reg_state.take() {
                Some(s) => s,
                None => return "ERR no reg state".into(),
            };
            match client::register_finish(state, password.as_bytes(), &resp_bytes) {
                Ok((upload, export_key)) => format!(
                    "OK {} {}",
                    BASE64_STANDARD.encode(upload),
                    BASE64_STANDARD.encode(export_key)
                ),
                Err(e) => format!("ERR {e:?}"),
            }
        }
        ["login-start", password] => match client::login_start(password.as_bytes()) {
            Ok((request, state)) => {
                *login_state = Some(state);
                format!("OK {}", BASE64_STANDARD.encode(request))
            }
            Err(e) => format!("ERR {e:?}"),
        },
        ["login-finish", password, resp_b64] => {
            // Decode base64 BEFORE consuming the stored state (see reg-finish): structural OPAQUE
            // errors are caught inside client::login_finish after the state is taken.
            let resp_bytes = match b64d(resp_b64) {
                Ok(b) => b,
                Err(e) => return format!("ERR {e}"),
            };
            let state = match login_state.take() {
                Some(s) => s,
                None => return "ERR no login state".into(),
            };
            match client::login_finish(state, password.as_bytes(), &resp_bytes) {
                Ok((finalization, session_key, export_key)) => format!(
                    "OK {} {} {}",
                    BASE64_STANDARD.encode(finalization),
                    BASE64_STANDARD.encode(session_key),
                    BASE64_STANDARD.encode(export_key)
                ),
                Err(e) => format!("ERR {e:?}"),
            }
        }
        _ => "ERR bad command".into(),
    }
}
