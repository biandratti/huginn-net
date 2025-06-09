use passivetcp_rs::tls::Ja4Fingerprint;
use passivetcp_rs::tls_parser::parse_tls_client_hello;

fn main() {
    // Example TLS ClientHello packet (simplified)
    let example_client_hello = create_example_client_hello();
    
    println!("🔐 TLS Fingerprinting Example");
    println!("==============================");
    
    match parse_tls_client_hello(&example_client_hello) {
        Ok(tls_sig) => {
            println!("\n📊 TLS Signature Analysis:");
            println!("TLS Version: {}", tls_sig.version);
            println!("Cipher Suites: {:?}", tls_sig.cipher_suites);
            println!("Extensions: {:?}", tls_sig.extensions);
            
            if let Some(sni) = &tls_sig.sni {
                println!("SNI: {}", sni);
            }
            
            // Generate JA4 fingerprint
            let ja4 = tls_sig.generate_ja4();
            println!("\n🚀 JA4 Fingerprint:");
            println!("  JA4_a: {}", ja4.ja4_a);
            println!("  JA4_b: {}", ja4.ja4_b);
            println!("  JA4_c: {}", ja4.ja4_c);
            println!("  JA4 Hash: {}", ja4.ja4_hash);
            
            // Demonstrate application detection
            detect_application(&ja4);
        }
        Err(e) => {
            eprintln!("❌ Failed to parse TLS: {}", e);
        }
    }
}

fn create_example_client_hello() -> Vec<u8> {
    // This is a simplified example - in real usage you'd capture this from network traffic
    vec![
        0x16, // TLS Handshake
        0x03, 0x03, // TLS 1.2
        0x00, 0x9c, // Length
        0x01, // ClientHello
        0x00, 0x00, 0x98, // Handshake length
        0x03, 0x03, // TLS version
        // Random (32 bytes) - simplified
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // Session ID length
        0x00, 0x08, // Cipher suites length
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x13, 0x02, // TLS_AES_256_GCM_SHA384
        0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
        0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0x01, // Compression methods length
        0x00, // No compression
        0x00, 0x45, // Extensions length
        // SNI Extension
        0x00, 0x00, // Server Name extension
        0x00, 0x0e, // Extension length
        0x00, 0x0c, // Server name list length
        0x00, // Hostname type
        0x00, 0x09, // Hostname length
        b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't',
        // Supported Groups
        0x00, 0x0a, // Supported groups extension
        0x00, 0x08, // Extension length
        0x00, 0x06, // Groups list length
        0x00, 0x1d, // x25519
        0x00, 0x17, // secp256r1
        0x00, 0x18, // secp384r1
        // EC Point Formats
        0x00, 0x0b, // EC point formats extension
        0x00, 0x02, // Extension length
        0x01, // Point formats length
        0x00, // Uncompressed
        // Signature Algorithms
        0x00, 0x0d, // Signature algorithms extension
        0x00, 0x08, // Extension length
        0x00, 0x06, // Algorithms list length
        0x04, 0x03, // ecdsa_secp256r1_sha256
        0x08, 0x04, // rsa_pss_rsae_sha256
        0x04, 0x01, // rsa_pkcs1_sha256
    ]
}

fn detect_application(ja4: &Ja4Fingerprint) {
    println!("\n🎯 Application Detection:");
    
    // JA4-based application detection
    // In a real implementation, you'd have a comprehensive database
    match ja4.ja4_hash.as_str() {
        "55d535c5dae9" => {
            println!("  🌐 Detected: Chrome Browser (JA4)");
        }
        "72a589da5868" => {
            println!("  🦊 Detected: Firefox Browser (JA4)");
        }
        "b32309a26951" => {
            println!("  📱 Detected: Safari Browser (JA4)");
        }
        _ => {
            println!("  ❓ Unknown application");
            println!("  💡 JA4: {} could be added to database", ja4.ja4_hash);
        }
    }
    
    // JA4_a provides detailed analysis
    if ja4.ja4_a.starts_with("13d") {
        println!("  ✅ TLS 1.3 with domain SNI detected");
    } else if ja4.ja4_a.starts_with("12d") {
        println!("  ⚠️  TLS 1.2 with domain SNI detected");
    } else if ja4.ja4_a.starts_with("13i") {
        println!("  🔒 TLS 1.3 with IP SNI detected");
    } else if ja4.ja4_a.starts_with("12i") {
        println!("  🔒 TLS 1.2 with IP SNI detected");
    }
    
    // Analyze cipher suite count
    let cipher_count = &ja4.ja4_a[2..4];
    if let Ok(count) = u8::from_str_radix(cipher_count, 16) {
        if count > 20 {
            println!("  📊 High cipher diversity ({} suites) - likely modern browser", count);
        } else if count < 5 {
            println!("  🤖 Low cipher diversity ({} suites) - likely automated tool", count);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example_parsing() {
        let client_hello = create_example_client_hello();
        let result = parse_tls_client_hello(&client_hello);
        assert!(result.is_ok());
        
        let tls_sig = result.unwrap();
        assert_eq!(tls_sig.version, TlsVersion::V1_2);
        assert!(!tls_sig.cipher_suites.is_empty());
        assert!(tls_sig.sni.is_some());
        assert_eq!(tls_sig.sni.unwrap(), "localhost");
    }



    #[test]
    fn test_ja4_generation() {
        let client_hello = create_example_client_hello();
        let tls_sig = parse_tls_client_hello(&client_hello).unwrap();
        let ja4 = tls_sig.generate_ja4();
        
        // JA4 components should have expected formats
        assert!(ja4.ja4_a.starts_with("12d")); // TLS 1.2 with domain
        assert!(!ja4.ja4_b.is_empty());
        assert!(!ja4.ja4_c.is_empty());
        assert_eq!(ja4.ja4_hash.len(), 12);
    }
} 