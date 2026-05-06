//! Process-local encryption key + AEAD wrappers for at-rest cache entries.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("decryption failed (tag mismatch)")]
    Decrypt,
}

/// 32-byte process-local key. Zeroized on drop. Safe to share via `Arc`.
pub struct CacheKey {
    inner: Zeroizing<[u8; 32]>,
}

impl CacheKey {
    pub fn new() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        CacheKey {
            inner: Zeroizing::new(bytes),
        }
    }

    pub fn seal(&self, plaintext: &[u8]) -> EncCacheEntry {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(self.inner.as_ref()));
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .expect("ChaCha20-Poly1305 encrypt: key and nonce lengths are statically correct");
        EncCacheEntry {
            nonce: nonce_bytes,
            ciphertext,
        }
    }

    pub fn open(&self, entry: &EncCacheEntry) -> Result<Vec<u8>, CryptoError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(self.inner.as_ref()));
        let nonce = Nonce::from_slice(&entry.nonce);
        cipher
            .decrypt(nonce, entry.ciphertext.as_ref())
            .map_err(|_| CryptoError::Decrypt)
    }
}

/// `Default::default()` generates a fresh random key — be aware when using
/// this in `#[derive(Default)]` on parent structs that the key is unique
/// per instantiation and is not recoverable.
impl Default for CacheKey {
    fn default() -> Self {
        Self::new()
    }
}

impl zeroize::Zeroize for CacheKey {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

/// Encrypted cache payload. Both fields zeroize on drop for hygiene.
#[derive(Debug, Clone)]
pub struct EncCacheEntry {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl Drop for EncCacheEntry {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.ciphertext.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = CacheKey::new();
        let plaintext = b"hello secret world";
        let entry = key.seal(plaintext);
        let opened = key.open(&entry).expect("decrypt");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn seal_produces_unique_nonce_per_call() {
        let key = CacheKey::new();
        let a = key.seal(b"same plaintext");
        let b = key.seal(b"same plaintext");
        assert_ne!(a.nonce, b.nonce, "nonces must differ");
        assert_ne!(a.ciphertext, b.ciphertext, "ciphertext must differ");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = CacheKey::new();
        let mut entry = key.seal(b"payload");
        entry.ciphertext[0] ^= 0x01;
        assert!(matches!(key.open(&entry), Err(CryptoError::Decrypt)));
    }

    #[test]
    fn tampered_nonce_fails() {
        let key = CacheKey::new();
        let mut entry = key.seal(b"payload");
        entry.nonce[0] ^= 0x01;
        assert!(matches!(key.open(&entry), Err(CryptoError::Decrypt)));
    }

    #[test]
    fn wrong_key_fails() {
        let key_a = CacheKey::new();
        let key_b = CacheKey::new();
        let entry = key_a.seal(b"only-a-can-read");
        assert!(matches!(key_b.open(&entry), Err(CryptoError::Decrypt)));
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let key = CacheKey::new();
        let entry = key.seal(b"");
        assert_eq!(key.open(&entry).unwrap(), b"");
    }
}
