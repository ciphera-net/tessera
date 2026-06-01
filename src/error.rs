use thiserror::Error;

/// All fallible Tessera operations return this error.
#[derive(Debug, Error)]
pub enum TesseraError {
    #[error("opaque protocol error: {0}")]
    Opaque(String),

    #[error("invalid base64 input: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("invalid wire message: {0}")]
    Protocol(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("unknown login id")]
    UnknownLogin,
}

// opaque_ke::errors::ProtocolError does not compose with thiserror #[from],
// so convert explicitly.
impl From<opaque_ke::errors::ProtocolError> for TesseraError {
    fn from(e: opaque_ke::errors::ProtocolError) -> Self {
        TesseraError::Opaque(format!("{e:?}"))
    }
}
