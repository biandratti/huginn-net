//! TLS Decryption Module
//!
//! This module provides TLS decryption capabilities using keylog files.
//! It supports TLS 1.2 and TLS 1.3 decryption with various cipher suites.

use crate::error::HuginnNetError;
use crate::tls_keylog::{KeyMaterial, KeyType, TlsKeylogManager};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use chacha20poly1305::{ChaCha20Poly1305, Key};
use std::collections::HashMap;
use tls_parser::TlsMessageHandshake;
use tracing::{debug, warn};

/// Supported TLS cipher suites for decryption
#[derive(Debug, Clone, PartialEq)]
pub enum CipherSuite {
    /// TLS_AES_128_GCM_SHA256 (TLS 1.3)
    Aes128GcmSha256,
    /// TLS_AES_256_GCM_SHA384 (TLS 1.3)
    Aes256GcmSha384,
    /// TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)
    ChaCha20Poly1305Sha256,
    /// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (TLS 1.2)
    EcdheRsaAes128GcmSha256,
    /// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (TLS 1.2)
    EcdheRsaAes256GcmSha384,
}

impl CipherSuite {
    /// Get cipher suite from TLS cipher suite identifier
    pub fn from_u16(cipher: u16) -> Option<Self> {
        match cipher {
            0x1301 => Some(Self::Aes128GcmSha256),
            0x1302 => Some(Self::Aes256GcmSha384),
            0x1303 => Some(Self::ChaCha20Poly1305Sha256),
            0xc02f => Some(Self::EcdheRsaAes128GcmSha256),
            0xc030 => Some(Self::EcdheRsaAes256GcmSha384),
            _ => None,
        }
    }

    /// Get key length in bytes for this cipher suite
    pub fn key_length(&self) -> usize {
        match self {
            Self::Aes128GcmSha256 | Self::EcdheRsaAes128GcmSha256 => 16,
            Self::Aes256GcmSha384 | Self::EcdheRsaAes256GcmSha384 => 32,
            Self::ChaCha20Poly1305Sha256 => 32,
        }
    }

    /// Get IV length in bytes for this cipher suite
    pub fn iv_length(&self) -> usize {
        match self {
            Self::Aes128GcmSha256 | Self::Aes256GcmSha384 => 12,
            Self::EcdheRsaAes128GcmSha256 | Self::EcdheRsaAes256GcmSha384 => 4,
            Self::ChaCha20Poly1305Sha256 => 12,
        }
    }

    /// Check if this is a TLS 1.3 cipher suite
    pub fn is_tls13(&self) -> bool {
        matches!(
            self,
            Self::Aes128GcmSha256 | Self::Aes256GcmSha384 | Self::ChaCha20Poly1305Sha256
        )
    }
}

/// TLS connection state for decryption
#[derive(Debug)]
pub struct TlsConnectionState {
    /// Client random from handshake
    pub client_random: Vec<u8>,
    /// Server random from handshake
    pub server_random: Vec<u8>,
    /// Negotiated cipher suite
    pub cipher_suite: CipherSuite,
    /// TLS version (0x0303 for TLS 1.2, 0x0304 for TLS 1.3)
    pub tls_version: u16,
    /// Client sequence number for record decryption
    pub client_seq_num: u64,
    /// Server sequence number for record decryption
    pub server_seq_num: u64,
}

impl TlsConnectionState {
    /// Create new TLS connection state
    pub fn new(
        client_random: Vec<u8>,
        server_random: Vec<u8>,
        cipher_suite: CipherSuite,
        tls_version: u16,
    ) -> Self {
        Self {
            client_random,
            server_random,
            cipher_suite,
            tls_version,
            client_seq_num: 0,
            server_seq_num: 0,
        }
    }
}

/// TLS decryption context
pub struct TlsDecryptor {
    /// Keylog manager for finding decryption keys
    keylog_manager: TlsKeylogManager,
    /// Active TLS connections being tracked
    connections: HashMap<String, TlsConnectionState>,
}

impl TlsDecryptor {
    /// Create new TLS decryptor with keylog manager
    pub fn new(keylog_manager: TlsKeylogManager) -> Self {
        Self {
            keylog_manager,
            connections: HashMap::new(),
        }
    }

    /// Process TLS handshake message to extract connection parameters
    pub fn process_handshake(
        &mut self,
        connection_id: &str,
        handshake_msg: &TlsMessageHandshake,
    ) -> Result<(), HuginnNetError> {
        match handshake_msg {
            TlsMessageHandshake::ClientHello(_client_hello) => {
                debug!("Processing ClientHello for connection: {}", connection_id);
                // Store client random for later use
                // Note: In a real implementation, we'd need to parse the full handshake
                // This is a simplified version for demonstration
            }
            TlsMessageHandshake::ServerHello(_server_hello) => {
                debug!("Processing ServerHello for connection: {}", connection_id);
                // Extract cipher suite and create connection state
                // This would need full handshake parsing in practice
            }
            _ => {
                // Other handshake messages
            }
        }

        Ok(())
    }

    /// Decrypt TLS application data record
    pub fn decrypt_record(
        &mut self,
        connection_id: &str,
        encrypted_data: &[u8],
        is_client_data: bool,
    ) -> Result<Vec<u8>, HuginnNetError> {
        // First, get the connection and extract needed data
        let (key_material, cipher_suite) = {
            let connection = self
                .connections
                .get(connection_id)
                .ok_or_else(|| HuginnNetError::Parse("Connection not found".to_string()))?;

            let key_material = self.find_key_material(connection, is_client_data)?;
            (key_material, connection.cipher_suite.clone())
        };

        // Now get mutable reference to connection for decryption
        let connection = self
            .connections
            .get_mut(connection_id)
            .ok_or_else(|| HuginnNetError::Parse("Connection not found".to_string()))?;

        // Decrypt based on cipher suite
        match &cipher_suite {
            CipherSuite::Aes128GcmSha256 | CipherSuite::Aes256GcmSha384 => {
                Self::decrypt_aes_gcm(encrypted_data, &key_material, connection, is_client_data)
            }
            CipherSuite::ChaCha20Poly1305Sha256 => Self::decrypt_chacha20_poly1305(
                encrypted_data,
                &key_material,
                connection,
                is_client_data,
            ),
            CipherSuite::EcdheRsaAes128GcmSha256 | CipherSuite::EcdheRsaAes256GcmSha384 => {
                Self::decrypt_tls12_aes_gcm(
                    encrypted_data,
                    &key_material,
                    connection,
                    is_client_data,
                )
            }
        }
    }

    /// Find appropriate key material for decryption
    fn find_key_material(
        &self,
        connection: &TlsConnectionState,
        is_client_data: bool,
    ) -> Result<KeyMaterial, HuginnNetError> {
        let key_type = if connection.cipher_suite.is_tls13() {
            if is_client_data {
                KeyType::ClientTrafficSecret0
            } else {
                KeyType::ServerTrafficSecret0
            }
        } else {
            // TLS 1.2 uses master secret
            KeyType::ClientRandom
        };

        let (_, key_material) = self
            .keylog_manager
            .find_key_by_type(&connection.client_random, &key_type)
            .ok_or_else(|| {
                HuginnNetError::Parse(format!(
                    "No key material found for connection with key type: {key_type:?}"
                ))
            })?;

        Ok(key_material.clone())
    }

    /// Decrypt AES-GCM encrypted data (TLS 1.3)
    fn decrypt_aes_gcm(
        encrypted_data: &[u8],
        key_material: &KeyMaterial,
        connection: &mut TlsConnectionState,
        is_client_data: bool,
    ) -> Result<Vec<u8>, HuginnNetError> {
        if encrypted_data.len() < 16 {
            return Err(HuginnNetError::Parse(
                "Encrypted data too short".to_string(),
            ));
        }

        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);

        // Get sequence number and increment
        let _seq_num = if is_client_data {
            let seq = connection.client_seq_num;
            connection.client_seq_num = connection.client_seq_num.saturating_add(1);
            seq
        } else {
            let seq = connection.server_seq_num;
            connection.server_seq_num = connection.server_seq_num.saturating_add(1);
            seq
        };

        match &connection.cipher_suite {
            CipherSuite::Aes128GcmSha256 => {
                let cipher = Aes128Gcm::new_from_slice(&key_material.key_data[..16])
                    .map_err(|e| HuginnNetError::Parse(format!("Invalid AES-128 key: {e}")))?;

                let nonce = Nonce::from_slice(nonce_bytes);

                cipher
                    .decrypt(nonce, ciphertext)
                    .map_err(|e| HuginnNetError::Parse(format!("AES-GCM decryption failed: {e}")))
            }
            CipherSuite::Aes256GcmSha384 => {
                let cipher = Aes256Gcm::new_from_slice(&key_material.key_data[..32])
                    .map_err(|e| HuginnNetError::Parse(format!("Invalid AES-256 key: {e}")))?;

                let nonce = Nonce::from_slice(nonce_bytes);

                cipher
                    .decrypt(nonce, ciphertext)
                    .map_err(|e| HuginnNetError::Parse(format!("AES-GCM decryption failed: {e}")))
            }
            _ => Err(HuginnNetError::Parse(
                "Invalid cipher suite for AES-GCM".to_string(),
            )),
        }
    }

    /// Decrypt ChaCha20-Poly1305 encrypted data (TLS 1.3)
    fn decrypt_chacha20_poly1305(
        encrypted_data: &[u8],
        key_material: &KeyMaterial,
        connection: &mut TlsConnectionState,
        is_client_data: bool,
    ) -> Result<Vec<u8>, HuginnNetError> {
        if encrypted_data.len() < 16 {
            return Err(HuginnNetError::Parse(
                "Encrypted data too short".to_string(),
            ));
        }

        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);

        // Get sequence number and increment
        let _seq_num = if is_client_data {
            let seq = connection.client_seq_num;
            connection.client_seq_num = connection.client_seq_num.saturating_add(1);
            seq
        } else {
            let seq = connection.server_seq_num;
            connection.server_seq_num = connection.server_seq_num.saturating_add(1);
            seq
        };

        let key = Key::from_slice(&key_material.key_data[..32]);
        let cipher = ChaCha20Poly1305::new(key);

        let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| HuginnNetError::Parse(format!("ChaCha20-Poly1305 decryption failed: {e}")))
    }

    /// Decrypt TLS 1.2 AES-GCM encrypted data
    fn decrypt_tls12_aes_gcm(
        _encrypted_data: &[u8],
        _key_material: &KeyMaterial,
        _connection: &mut TlsConnectionState,
        _is_client_data: bool,
    ) -> Result<Vec<u8>, HuginnNetError> {
        // TLS 1.2 decryption is more complex as it requires deriving keys from master secret
        // This is a simplified implementation
        warn!("TLS 1.2 decryption not fully implemented yet");
        Err(HuginnNetError::Parse(
            "TLS 1.2 decryption not implemented".to_string(),
        ))
    }

    /// Add a new TLS connection to track
    pub fn add_connection(&mut self, connection_id: String, state: TlsConnectionState) {
        debug!("Adding TLS connection: {}", connection_id);
        self.connections.insert(connection_id, state);
    }

    /// Remove a TLS connection
    pub fn remove_connection(&mut self, connection_id: &str) {
        debug!("Removing TLS connection: {}", connection_id);
        self.connections.remove(connection_id);
    }

    /// Get connection count
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Check if a connection exists
    pub fn has_connection(&self, connection_id: &str) -> bool {
        self.connections.contains_key(connection_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_suite_from_u16() {
        assert_eq!(
            CipherSuite::from_u16(0x1301),
            Some(CipherSuite::Aes128GcmSha256)
        );
        assert_eq!(
            CipherSuite::from_u16(0x1302),
            Some(CipherSuite::Aes256GcmSha384)
        );
        assert_eq!(
            CipherSuite::from_u16(0x1303),
            Some(CipherSuite::ChaCha20Poly1305Sha256)
        );
        assert_eq!(CipherSuite::from_u16(0x9999), None);
    }

    #[test]
    fn test_cipher_suite_properties() {
        let aes128 = CipherSuite::Aes128GcmSha256;
        assert_eq!(aes128.key_length(), 16);
        assert_eq!(aes128.iv_length(), 12);
        assert!(aes128.is_tls13());

        let aes256 = CipherSuite::Aes256GcmSha384;
        assert_eq!(aes256.key_length(), 32);
        assert_eq!(aes256.iv_length(), 12);
        assert!(aes256.is_tls13());

        let tls12_cipher = CipherSuite::EcdheRsaAes128GcmSha256;
        assert_eq!(tls12_cipher.key_length(), 16);
        assert_eq!(tls12_cipher.iv_length(), 4);
        assert!(!tls12_cipher.is_tls13());
    }

    #[test]
    fn test_tls_connection_state() {
        let client_random = vec![1u8; 32];
        let server_random = vec![2u8; 32];
        let cipher_suite = CipherSuite::Aes128GcmSha256;
        let tls_version = 0x0304; // TLS 1.3

        let state = TlsConnectionState::new(
            client_random.clone(),
            server_random.clone(),
            cipher_suite.clone(),
            tls_version,
        );

        assert_eq!(state.client_random, client_random);
        assert_eq!(state.server_random, server_random);
        assert_eq!(state.cipher_suite, cipher_suite);
        assert_eq!(state.tls_version, tls_version);
        assert_eq!(state.client_seq_num, 0);
        assert_eq!(state.server_seq_num, 0);
    }

    #[test]
    fn test_tls_decryptor_creation() {
        let keylog_manager = TlsKeylogManager::new();
        let decryptor = TlsDecryptor::new(keylog_manager);

        assert_eq!(decryptor.connection_count(), 0);
        assert!(!decryptor.has_connection("test"));
    }

    #[test]
    fn test_connection_management() {
        let keylog_manager = TlsKeylogManager::new();
        let mut decryptor = TlsDecryptor::new(keylog_manager);

        let state = TlsConnectionState::new(
            vec![1u8; 32],
            vec![2u8; 32],
            CipherSuite::Aes128GcmSha256,
            0x0304,
        );

        decryptor.add_connection("test_conn".to_string(), state);
        assert_eq!(decryptor.connection_count(), 1);
        assert!(decryptor.has_connection("test_conn"));

        decryptor.remove_connection("test_conn");
        assert_eq!(decryptor.connection_count(), 0);
        assert!(!decryptor.has_connection("test_conn"));
    }
}
