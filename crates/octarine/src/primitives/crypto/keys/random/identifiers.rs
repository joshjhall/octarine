//! Random identifier generation (UUID, hex, base64).

use super::{CryptoError, random_bytes, random_bytes_vec};

// ============================================================================
// Identifier Generation
// ============================================================================

/// Generate a random UUID v4.
///
/// Returns a standard UUID v4 string in the format:
/// `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::random_uuid_v4;
///
/// let id = random_uuid_v4()?;
/// // e.g., "f47ac10b-58cc-4372-a567-0e02b2c3d479"
/// ```
pub fn random_uuid_v4() -> Result<String, CryptoError> {
    let mut bytes = random_bytes::<16>()?;

    // Set version (4) in bits 12-15 of time_hi_and_version
    bytes[6] = (bytes[6] & 0x0f) | 0x40;

    // Set variant (10xx) in bits 0-1 of clock_seq_hi_and_reserved
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    ))
}

/// Generate a random hex string.
///
/// # Arguments
///
/// * `byte_len` - The number of random bytes (hex string will be 2x this length)
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::random_hex;
///
/// let token = random_hex(16)?; // 32-character hex string
/// ```
pub fn random_hex(byte_len: usize) -> Result<String, CryptoError> {
    let bytes = random_bytes_vec(byte_len)?;

    let hex_chars: &[u8] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len().saturating_mul(2));

    for byte in bytes {
        let hi = byte >> 4;
        let lo = byte & 0x0f;
        hex.push(char::from(
            hex_chars.get(hi as usize).copied().unwrap_or(b'0'),
        ));
        hex.push(char::from(
            hex_chars.get(lo as usize).copied().unwrap_or(b'0'),
        ));
    }

    Ok(hex)
}

/// Generate a random base64-encoded string.
///
/// Uses standard base64 encoding (with `+` and `/`).
///
/// # Arguments
///
/// * `byte_len` - The number of random bytes to encode
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::random_base64;
///
/// let token = random_base64(32)?; // ~44 character base64 string
/// ```
pub fn random_base64(byte_len: usize) -> Result<String, CryptoError> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let bytes = random_bytes_vec(byte_len)?;
    Ok(STANDARD.encode(&bytes))
}

/// Generate a random URL-safe base64-encoded string.
///
/// Uses URL-safe base64 encoding (with `-` and `_`, no padding).
///
/// # Arguments
///
/// * `byte_len` - The number of random bytes to encode
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::random_base64_url;
///
/// let token = random_base64_url(32)?; // URL-safe token
/// ```
pub fn random_base64_url(byte_len: usize) -> Result<String, CryptoError> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let bytes = random_bytes_vec(byte_len)?;
    Ok(URL_SAFE_NO_PAD.encode(&bytes))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_random_uuid_v4() {
        let uuid = random_uuid_v4().expect("UUID");

        // Check format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
        assert_eq!(uuid.len(), 36);
        assert_eq!(uuid.get(8..9).expect("uuid has char at index 8"), "-");
        assert_eq!(uuid.get(13..14).expect("uuid has char at index 13"), "-");
        assert_eq!(uuid.get(14..15).expect("uuid has char at index 14"), "4"); // Version 4
        assert_eq!(uuid.get(18..19).expect("uuid has char at index 18"), "-");
        // Variant should be 8, 9, a, or b
        let variant = uuid.get(19..20).expect("uuid has char at index 19");
        assert!(["8", "9", "a", "b"].contains(&variant));
        assert_eq!(uuid.get(23..24).expect("uuid has char at index 23"), "-");
    }

    #[test]
    fn test_random_hex() {
        let hex = random_hex(16).expect("Hex");
        assert_eq!(hex.len(), 32);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_random_base64() {
        let b64 = random_base64(24).expect("Base64");
        assert_eq!(b64.len(), 32); // 24 bytes = 32 base64 chars

        let b64_url = random_base64_url(24).expect("Base64 URL");
        assert!(!b64_url.contains('+')); // URL-safe doesn't use +
        assert!(!b64_url.contains('/')); // URL-safe doesn't use /
    }
}
