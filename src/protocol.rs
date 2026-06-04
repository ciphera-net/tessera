use std::fmt;
use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

/// Upper bound on a single frame (1 MiB). OPAQUE messages are a few hundred
/// bytes; anything larger is malformed or hostile.
pub const MAX_FRAME: usize = 1024 * 1024;

/// Requests from the Go SDK to the sidecar. Internally tagged by an `op` field whose value
/// is the snake_case variant name, e.g. `{"op":"register_start", ...}`.
// Debug is implemented MANUALLY (below) to redact secret-bearing fields (password_file_b64). A blanket
// #[derive(Debug)] would let an accidental future `eprintln!("{:?}", req)` leak the OPAQUE credential record.
#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    RegisterStart {
        request_b64: String,
        credential_id: String,
    },
    RegisterFinish {
        upload_b64: String,
    },
    LoginStart {
        request_b64: String,
        /// The server's stored OPAQUE credential record (base64). `None` for an unknown
        /// account — the sidecar then lets opaque-ke produce a timing-safe fake response,
        /// so the protocol never reveals whether the account exists (user-enumeration safe).
        password_file_b64: Option<String>,
        credential_id: String,
    },
    LoginFinish {
        login_id: String,
        finalization_b64: String,
    },
}

/// Responses from the sidecar to the Go SDK. Internally tagged by a `result` field whose
/// value is the snake_case variant name, e.g. `{"result":"login_finish", ...}`. The
/// `Error` variant carries a human-readable message.
// Debug is implemented MANUALLY (below) to redact secret-bearing fields (password_file_b64, session_key_b64).
#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    RegisterStart {
        response_b64: String,
    },
    RegisterFinish {
        password_file_b64: String,
    },
    LoginStart {
        login_id: String,
        response_b64: String,
    },
    LoginFinish {
        session_key_b64: String,
    },
    Error {
        code: String,
        message: String,
    },
}

// Manual Debug impls redact secret-bearing fields so an accidental `{:?}` log never leaks the OPAQUE
// credential record (password_file_b64) or a session key. Non-secret identifiers (credential_id,
// login_id) are kept for debuggability; the bulky public OPAQUE blobs are omitted (`..`).
impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Request::RegisterStart { credential_id, .. } => f
                .debug_struct("RegisterStart")
                .field("credential_id", credential_id)
                .finish_non_exhaustive(),
            Request::RegisterFinish { .. } => {
                f.debug_struct("RegisterFinish").finish_non_exhaustive()
            }
            Request::LoginStart {
                credential_id,
                password_file_b64,
                ..
            } => f
                .debug_struct("LoginStart")
                .field("credential_id", credential_id)
                .field(
                    "password_file_b64",
                    &password_file_b64.as_ref().map(|_| "<redacted>"),
                )
                .finish_non_exhaustive(),
            Request::LoginFinish { login_id, .. } => f
                .debug_struct("LoginFinish")
                .field("login_id", login_id)
                .finish_non_exhaustive(),
        }
    }
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Response::RegisterStart { .. } => {
                f.debug_struct("RegisterStart").finish_non_exhaustive()
            }
            Response::RegisterFinish { .. } => f
                .debug_struct("RegisterFinish")
                .field("password_file_b64", &"<redacted>")
                .finish_non_exhaustive(),
            Response::LoginStart { login_id, .. } => f
                .debug_struct("LoginStart")
                .field("login_id", login_id)
                .finish_non_exhaustive(),
            Response::LoginFinish { .. } => f
                .debug_struct("LoginFinish")
                .field("session_key_b64", &"<redacted>")
                .finish_non_exhaustive(),
            Response::Error { code, message } => f
                .debug_struct("Error")
                .field("code", code)
                .field("message", message)
                .finish(),
        }
    }
}

/// Write a length-prefixed frame: `[u32 big-endian length][payload]`. Flushes the writer so
/// the frame is actually transmitted — important for the request/response cycle and required
/// when `W` is buffered (e.g. a `BufWriter`); on an unbuffered `UnixStream` the flush is a
/// harmless no-op.
pub fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "payload too large"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

/// Read a length-prefixed frame, rejecting anything larger than `MAX_FRAME`.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds MAX_FRAME",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frame_round_trips() {
        let payload = b"hello tessera";
        let mut buf = Vec::new();
        write_frame(&mut buf, payload).unwrap();
        let mut cursor = Cursor::new(buf);
        let got = read_frame(&mut cursor).unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn request_serializes_as_tagged_json() {
        let req = Request::RegisterStart {
            request_b64: "AAA".into(),
            credential_id: "creds-123".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"op\":\"register_start\""));
        let back: Request = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Request::RegisterStart { .. }));
    }

    #[test]
    fn oversized_frame_is_rejected() {
        // length prefix claims 100 MiB; must error rather than allocate.
        let mut buf = (100u32 * 1024 * 1024).to_be_bytes().to_vec();
        buf.extend_from_slice(b"x");
        let mut cursor = Cursor::new(buf);
        assert!(read_frame(&mut cursor).is_err());
    }

    #[test]
    fn response_serializes_as_tagged_json() {
        let resp = Response::LoginFinish {
            session_key_b64: "ZZZ".into(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"result\":\"login_finish\""));
        let back: Response = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Response::LoginFinish { .. }));
    }

    #[test]
    fn error_response_carries_code_and_message() {
        // Pins the wire shape the Go SDK (Phase 2B) decodes: a tagged `error` result with BOTH a
        // stable `code` and a human `message`. Renaming/removing the `code` field breaks this.
        let resp = Response::Error {
            code: "bad_request".into(),
            message: "boom".into(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"result\":\"error\""));
        assert!(json.contains("\"code\":\"bad_request\""));
        assert!(json.contains("\"message\":\"boom\""));
        let back: Response = serde_json::from_str(&json).unwrap();
        assert!(
            matches!(back, Response::Error { code, message } if code == "bad_request" && message == "boom")
        );
    }
}
