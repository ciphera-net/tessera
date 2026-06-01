use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

/// Upper bound on a single frame (1 MiB). OPAQUE messages are a few hundred
/// bytes; anything larger is malformed or hostile.
pub const MAX_FRAME: usize = 1024 * 1024;

/// Requests from the Go SDK to the sidecar. Internally tagged by an `op` field whose value
/// is the snake_case variant name, e.g. `{"op":"register_start", ...}`.
#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
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
        message: String,
    },
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
}
