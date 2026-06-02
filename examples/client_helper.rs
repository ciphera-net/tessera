//! OPAQUE client-side test helper (dev/CI only — an examples/ target, never shipped in the
//! sidecar image). Drives the client steps via a line protocol on stdin/stdout so an integration
//! test in another language can relay messages to a real `tessera-sidecar`.
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
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use rand::rngs::OsRng;
use tessera::suite::TesseraCipherSuite;

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    let mut reg_state: Option<ClientRegistration<TesseraCipherSuite>> = None;
    let mut login_state: Option<ClientLogin<TesseraCipherSuite>> = None;
    let mut rng = OsRng;

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
        let reply = handle(&parts, &mut reg_state, &mut login_state, &mut rng);
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
    reg_state: &mut Option<ClientRegistration<TesseraCipherSuite>>,
    login_state: &mut Option<ClientLogin<TesseraCipherSuite>>,
    rng: &mut OsRng,
) -> String {
    match parts {
        ["reg-start", password] => {
            match ClientRegistration::<TesseraCipherSuite>::start(rng, password.as_bytes()) {
                Ok(c) => {
                    let msg = BASE64_STANDARD.encode(c.message.serialize());
                    *reg_state = Some(c.state);
                    format!("OK {msg}")
                }
                Err(e) => format!("ERR {e:?}"),
            }
        }
        ["reg-finish", password, resp_b64] => {
            // Validate inputs BEFORE consuming the stored state: a bad response must leave the
            // state intact and report the real decode error, not a misleading "no reg state".
            let resp_bytes = match b64d(resp_b64) {
                Ok(b) => b,
                Err(e) => return format!("ERR {e}"),
            };
            let resp = match RegistrationResponse::deserialize(&resp_bytes) {
                Ok(r) => r,
                Err(e) => return format!("ERR {e:?}"),
            };
            let state = match reg_state.take() {
                Some(s) => s,
                None => return "ERR no reg state".into(),
            };
            match state.finish(
                rng,
                password.as_bytes(),
                resp,
                ClientRegistrationFinishParameters::default(),
            ) {
                Ok(f) => format!(
                    "OK {} {}",
                    BASE64_STANDARD.encode(f.message.serialize()),
                    BASE64_STANDARD.encode(f.export_key)
                ),
                Err(e) => format!("ERR {e:?}"),
            }
        }
        ["login-start", password] => {
            match ClientLogin::<TesseraCipherSuite>::start(rng, password.as_bytes()) {
                Ok(c) => {
                    let msg = BASE64_STANDARD.encode(c.message.serialize());
                    *login_state = Some(c.state);
                    format!("OK {msg}")
                }
                Err(e) => format!("ERR {e:?}"),
            }
        }
        ["login-finish", password, resp_b64] => {
            // Validate inputs BEFORE consuming the stored state (see reg-finish).
            let resp_bytes = match b64d(resp_b64) {
                Ok(b) => b,
                Err(e) => return format!("ERR {e}"),
            };
            let resp = match CredentialResponse::deserialize(&resp_bytes) {
                Ok(r) => r,
                Err(e) => return format!("ERR {e:?}"),
            };
            let state = match login_state.take() {
                Some(s) => s,
                None => return "ERR no login state".into(),
            };
            match state.finish(
                rng,
                password.as_bytes(),
                resp,
                ClientLoginFinishParameters::default(),
            ) {
                Ok(f) => format!(
                    "OK {} {} {}",
                    BASE64_STANDARD.encode(f.message.serialize()),
                    BASE64_STANDARD.encode(f.session_key),
                    BASE64_STANDARD.encode(f.export_key)
                ),
                Err(e) => format!("ERR {e:?}"),
            }
        }
        _ => "ERR bad command".into(),
    }
}
