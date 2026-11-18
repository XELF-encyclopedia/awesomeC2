//! Session-crypto interface for the C2 client (M0 slice).
//!
//! M0 ships a plaintext implementation so the end-to-end loopback slice builds
//! with zero third-party crates (`cargo build --offline`).
//!
//! The interface is shaped for the v2 target suite:
//!   X25519 (ephemeral ECDH) -> HKDF-SHA256 -> AES-256-GCM or ChaCha20-Poly1305
//!
//! `Suite::V2` returns `CryptoError::Unsupported` until the real primitives land
//! (M1). This is deliberate: no caller can mistake plaintext for encryption.

#![allow(dead_code)] // interface + error variants are used from M1 onwards

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    /// M0 only: no confidentiality. Loopback / lab transport testing.
    Plaintext,
    /// Target suite: X25519 + HKDF-SHA256 + AES-256-GCM (preferred) or
    /// ChaCha20-Poly1305; implemented in M1.
    V2,
}

impl fmt::Display for Suite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Suite::Plaintext => write!(f, "plaintext"),
            Suite::V2 => write!(f, "v2-x25519-aead"),
        }
    }
}

#[derive(Debug)]
pub enum CryptoError {
    Unsupported(&'static str),
    /// AEAD tag mismatch / malformed frame.
    AuthFailed,
    /// Frame or key material too short/long.
    Length(&'static str),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::Unsupported(m) => write!(f, "unsupported: {m}"),
            CryptoError::AuthFailed => write!(f, "authentication failed"),
            CryptoError::Length(m) => write!(f, "bad length: {m}"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Per-session cipher state, applied to whole frames (the frame codec adds the
/// 4-byte length prefix; AAD is the literal `b"frame"` domain separator).
pub trait SessionCipher: Send {
    fn suite(&self) -> Suite;
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// M0 transport cipher: identity transform. Loopback/lab only; the frame's
/// `suite` field tells a future server which suite was negotiated.
pub struct Plaintext;

impl SessionCipher for Plaintext {
    fn suite(&self) -> Suite {
        Suite::Plaintext
    }
    fn seal(&mut self, _aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(plaintext.to_vec())
    }
    fn open(&mut self, _aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(ciphertext.to_vec())
    }
}

/// Factory used by the transport layer. `--suite plaintext|v2` selects it.
pub fn new_cipher(suite: Suite) -> Result<Box<dyn SessionCipher>, CryptoError> {
    match suite {
        Suite::Plaintext => Ok(Box::new(Plaintext)),
        Suite::V2 => Err(CryptoError::Unsupported(
            "v2 suite (X25519+HKDF+AES-256-GCM/ChaCha20-Poly1305) lands in M1",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_is_identity() {
        let mut c = new_cipher(Suite::Plaintext).unwrap();
        let ct = c.seal(b"frame", b"hello").unwrap();
        assert_eq!(ct, b"hello");
        assert_eq!(c.open(b"frame", &ct).unwrap(), b"hello");
        assert_eq!(c.suite(), Suite::Plaintext);
    }

    #[test]
    fn v2_is_explicitly_unsupported_in_m0() {
        match new_cipher(Suite::V2) {
            Err(CryptoError::Unsupported(_)) => {}
            other => panic!("expected Unsupported, got {:?}", other.map(|_| ())),
        }
    }
}
