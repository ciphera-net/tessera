use thiserror::Error;

/// All fallible Tessera operations return this error.
#[derive(Debug, Error)]
pub enum TesseraError {
    #[error("opaque protocol error: {0}")]
    Opaque(#[from] opaque_ke::errors::ProtocolError),

    #[error("invalid base64 input: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("invalid wire message: {0}")]
    Protocol(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("unknown login id")]
    UnknownLogin,
}
