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

impl TesseraError {
    /// Stable error code for the wire protocol. Lets clients branch on error class
    /// (e.g. HTTP 401 vs 400 vs 500) without matching on human-readable messages, which are
    /// not a stable contract. The OPAQUE protocol errors are split by class: a failed credential
    /// check (`InvalidLoginError`) is an authentication failure distinct from a malformed/tampered
    /// message or an internal crypto fault.
    pub fn code(&self) -> &'static str {
        use opaque_ke::errors::ProtocolError;
        match self {
            TesseraError::UnknownLogin => "unknown_login",
            TesseraError::Base64(_) | TesseraError::Protocol(_) => "bad_request",
            TesseraError::Opaque(e) => match e {
                // Credential verification failed — the client proved the wrong password (401).
                ProtocolError::InvalidLoginError => "invalid_credentials",
                // Malformed or tampered OPAQUE message from the client (400).
                ProtocolError::SerializationError
                | ProtocolError::SizeError { .. }
                | ProtocolError::ReflectedValueError => "bad_request",
                // LibraryError (and the uninhabited Custom) — an internal crypto fault (500).
                _ => "internal",
            },
            TesseraError::Io(_) => "internal",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_ke::errors::ProtocolError;

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(TesseraError::UnknownLogin.code(), "unknown_login");
        assert_eq!(TesseraError::Protocol("x".into()).code(), "bad_request");
        // OPAQUE: a wrong-password rejection (InvalidLoginError) is an auth failure (401) and MUST
        // stay distinguishable on the wire from a malformed message (400) or an internal fault (500).
        assert_eq!(
            TesseraError::Opaque(ProtocolError::InvalidLoginError).code(),
            "invalid_credentials"
        );
        assert_eq!(
            TesseraError::Opaque(ProtocolError::SerializationError).code(),
            "bad_request"
        );
        assert_eq!(
            TesseraError::Opaque(ProtocolError::ReflectedValueError).code(),
            "bad_request"
        );
        assert_eq!(
            TesseraError::Io(std::io::Error::from(std::io::ErrorKind::Other)).code(),
            "internal"
        );
    }
}
