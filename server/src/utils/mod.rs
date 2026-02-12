// Utility functions

use sha2::{Digest, Sha256};

/// Hash an API key for storage
pub fn hash_api_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Generate a new API key
pub fn generate_api_key() -> (String, String) {
    let key = format!("ora_{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
    let prefix = key[..12].to_string();
    (key, prefix)
}

/// Hash a prompt for caching
pub fn hash_prompt(prompt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prompt.as_bytes());
    format!("{:x}", hasher.finalize())
}

// ============================================
// AES-256-GCM Encryption for Model API Keys
// ============================================

pub mod encryption {
    use aes_gcm::{
        Aes256Gcm, Nonce,
        aead::{Aead, KeyInit, OsRng},
    };
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
    use rand::RngCore;
    use sha2::{Digest, Sha256};

    /// Derive a 256-bit key from the encryption secret using SHA-256.
    /// In production, use a proper KDF like HKDF or Argon2.
    fn derive_key(secret: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    /// Get the encryption key from environment.
    /// Falls back to JWT_SECRET if ENCRYPTION_KEY is not set.
    fn get_encryption_key() -> String {
        std::env::var("ENCRYPTION_KEY")
            .or_else(|_| std::env::var("JWT_SECRET"))
            .expect("ENCRYPTION_KEY or JWT_SECRET must be set for model API key encryption")
    }

    /// Encrypt plaintext using AES-256-GCM.
    /// Returns base64-encoded string: nonce(12 bytes) || ciphertext || tag(16 bytes)
    pub fn encrypt(plaintext: &str) -> Result<String, String> {
        let secret = get_encryption_key();
        let key_bytes = derive_key(&secret);
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| format!("Encryption failed: {}", e))?;

        // Prepend nonce to ciphertext
        let mut combined = Vec::with_capacity(12 + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);

        Ok(BASE64.encode(&combined))
    }

    /// Decrypt base64-encoded AES-256-GCM ciphertext.
    /// Expects: nonce(12 bytes) || ciphertext || tag(16 bytes)
    #[allow(dead_code)]
    pub fn decrypt(encrypted: &str) -> Result<String, String> {
        let secret = get_encryption_key();
        let key_bytes = derive_key(&secret);
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;

        let combined = BASE64
            .decode(encrypted)
            .map_err(|e| format!("Base64 decode failed: {}", e))?;

        if combined.len() < 12 {
            return Err("Encrypted data too short".to_string());
        }

        let (nonce_bytes, ciphertext) = combined.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {}", e))?;

        String::from_utf8(plaintext).map_err(|e| format!("UTF-8 decode failed: {}", e))
    }
}
