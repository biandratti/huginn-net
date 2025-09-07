//! TLS Decryption Example
//!
//! This example demonstrates how to use the TLS decryption capabilities
//! with keylog files to decrypt HTTPS traffic.

use huginn_net::tls_decryption::{CipherSuite, TlsConnectionState, TlsDecryptor};
use huginn_net::tls_keylog::TlsKeylogManager;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("TLS Decryption Example");
    println!("=====================");

    // Example 1: Create TLS decryptor with keylog
    println!("\n--- Creating TLS Decryptor ---");

    let keylog_content = r#"
# Example keylog for TLS 1.3 session
CLIENT_RANDOM 1111111111111111111111111111111111111111111111111111111111111111 fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
CLIENT_TRAFFIC_SECRET_0 1111111111111111111111111111111111111111111111111111111111111111 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
SERVER_TRAFFIC_SECRET_0 1111111111111111111111111111111111111111111111111111111111111111 9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba
"#;

    let mut keylog_manager = TlsKeylogManager::new();
    keylog_manager.add_keylog_from_string("example.com".to_string(), keylog_content)?;

    let mut decryptor = TlsDecryptor::new(keylog_manager);

    println!("Created TLS decryptor with keylog manager");
    println!("  Keylog count: {}", decryptor.connection_count());

    // Example 2: Add TLS connection
    println!("\n--- Adding TLS Connection ---");

    let client_random =
        hex::decode("1111111111111111111111111111111111111111111111111111111111111111")?;
    let server_random =
        hex::decode("2222222222222222222222222222222222222222222222222222222222222222")?;

    let connection_state = TlsConnectionState::new(
        client_random,
        server_random,
        CipherSuite::Aes128GcmSha256,
        0x0304, // TLS 1.3
    );

    decryptor.add_connection("conn_1".to_string(), connection_state);

    println!("Added TLS connection:");
    println!("  Connection ID: conn_1");
    println!("  Cipher Suite: AES-128-GCM-SHA256");
    println!("  TLS Version: 1.3");
    println!("  Active connections: {}", decryptor.connection_count());

    // Example 3: Demonstrate cipher suite capabilities
    println!("\n--- Cipher Suite Information ---");

    let cipher_suites = vec![
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::ChaCha20Poly1305Sha256,
        CipherSuite::EcdheRsaAes128GcmSha256,
        CipherSuite::EcdheRsaAes256GcmSha384,
    ];

    for cipher in cipher_suites {
        println!("Cipher Suite: {cipher:?}");
        println!("  Key Length: {} bytes", cipher.key_length());
        println!("  IV Length: {} bytes", cipher.iv_length());
        println!("  TLS 1.3: {}", cipher.is_tls13());

        // Show cipher suite ID
        let cipher_id = match cipher {
            CipherSuite::Aes128GcmSha256 => Some(0x1301),
            CipherSuite::Aes256GcmSha384 => Some(0x1302),
            CipherSuite::ChaCha20Poly1305Sha256 => Some(0x1303),
            CipherSuite::EcdheRsaAes128GcmSha256 => Some(0xc02f),
            CipherSuite::EcdheRsaAes256GcmSha384 => Some(0xc030),
        };

        if let Some(id) = cipher_id {
            println!("  Cipher ID: 0x{id:04x}");

            // Verify round-trip conversion
            if let Some(parsed_cipher) = CipherSuite::from_u16(id) {
                assert_eq!(parsed_cipher, cipher);
                println!("  ✓ Round-trip conversion successful");
            }
        }
        println!();
    }

    // Example 4: Connection management
    println!("\n--- Connection Management ---");

    // Add more connections
    let connection_2 = TlsConnectionState::new(
        hex::decode("3333333333333333333333333333333333333333333333333333333333333333")?,
        hex::decode("4444444444444444444444444444444444444444444444444444444444444444")?,
        CipherSuite::ChaCha20Poly1305Sha256,
        0x0304,
    );

    let connection_3 = TlsConnectionState::new(
        hex::decode("5555555555555555555555555555555555555555555555555555555555555555")?,
        hex::decode("6666666666666666666666666666666666666666666666666666666666666666")?,
        CipherSuite::EcdheRsaAes256GcmSha384,
        0x0303, // TLS 1.2
    );

    decryptor.add_connection("conn_2".to_string(), connection_2);
    decryptor.add_connection("conn_3".to_string(), connection_3);

    println!("Added additional connections:");
    println!("  Total connections: {}", decryptor.connection_count());
    println!("  Has conn_1: {}", decryptor.has_connection("conn_1"));
    println!("  Has conn_2: {}", decryptor.has_connection("conn_2"));
    println!("  Has conn_3: {}", decryptor.has_connection("conn_3"));
    println!("  Has conn_4: {}", decryptor.has_connection("conn_4"));

    // Remove a connection
    decryptor.remove_connection("conn_2");
    println!("\nAfter removing conn_2:");
    println!("  Total connections: {}", decryptor.connection_count());
    println!("  Has conn_2: {}", decryptor.has_connection("conn_2"));

    // Example 5: Demonstrate decryption attempt (will fail without real encrypted data)
    println!("\n--- Decryption Demonstration ---");

    // This is just a demonstration - real encrypted data would be needed
    let fake_encrypted_data = vec![0u8; 32]; // Fake encrypted data

    match decryptor.decrypt_record("conn_1", &fake_encrypted_data, true) {
        Ok(decrypted) => {
            println!("✓ Decryption successful: {} bytes", decrypted.len());
        }
        Err(e) => {
            println!("✗ Decryption failed (expected): {e}");
            println!("  Note: This is expected with fake data");
        }
    }

    // Try with non-existent connection
    match decryptor.decrypt_record("non_existent", &fake_encrypted_data, true) {
        Ok(_) => {
            println!("✗ Unexpected success");
        }
        Err(e) => {
            println!("✓ Expected error for non-existent connection: {e}");
        }
    }

    println!("\n--- Summary ---");
    println!("TLS Decryption module provides:");
    println!("  • Support for TLS 1.2 and TLS 1.3");
    println!("  • Multiple cipher suites (AES-GCM, ChaCha20-Poly1305)");
    println!("  • Integration with keylog files");
    println!("  • Connection state management");
    println!("  • Sequence number tracking for decryption");
    println!("\nNext steps would be:");
    println!("  • Integrate with packet capture");
    println!("  • Parse TLS handshake messages");
    println!("  • Extract real encrypted application data");
    println!("  • Decrypt and forward to HTTP processing");

    Ok(())
}
