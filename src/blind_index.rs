//! Deterministic, privacy-preserving account lookup key. CROSS-LANGUAGE PARITY CONTRACT with
//! `tessera-go/blindindex.go`: identical normalization, Argon2id params, salt, and output length.

use opaque_ke::argon2::{Algorithm, Argon2, Params, Version};

/// Fixed, NON-SECRET, versioned domain-separation salt (ships in client code). Distinct from
/// opaque-ke's INTERNAL KSF salt (16 zero bytes) — changing this is a BREAKING parity change.
const BLIND_INDEX_SALT: &[u8] = b"tessera/blind-index/v1";
const _: () = assert!(
    BLIND_INDEX_SALT.len() == 22,
    "blind-index salt changed — breaks tessera-go parity"
);

/// Normalize: TrimSpace THEN ToLower (order is part of the parity contract; no NFC/IDNA in v1).
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Argon2id(V0x13, t=3, m=64 MiB, p=1) over the normalized email → 32 bytes.
/// `Some(32)` is REQUIRED: `hash_password_into` writes exactly the buffer length here (a fixed
/// `[0u8; 32]`), and `output_len` must permit 32. (Contrast the OPAQUE KSF, which uses `None`
/// because opaque-ke passes a 64-byte buffer — see `client.rs`.) p=1: WASM Argon2 is single-lane.
pub fn blind_index_bytes(email: &str) -> Result<[u8; 32], opaque_ke::argon2::Error> {
    let norm = normalize_email(email);
    let params = Params::new(65_536, 3, 1, Some(32))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2.hash_password_into(norm.as_bytes(), BLIND_INDEX_SALT, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalization_is_trim_then_lower() {
        assert_eq!(normalize_email("  User@Example.COM \t"), "user@example.com");
    }
    #[test]
    fn output_is_32_bytes_and_deterministic() {
        let a = blind_index_bytes("user@example.com").unwrap();
        let b = blind_index_bytes(" USER@example.com ").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }
}
