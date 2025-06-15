use passivetcp_rs::tls::{TlsSignature, TlsVersion};
use tracing::{info, debug, Level};
use tracing_subscriber;

fn main() {
    // Initialize detailed logging
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    info!("=== TLS Parser Debugging ===");
    
    // Expected values from your browser (from the ja4_fingerprint_string)
    let expected_ciphers = vec![
        0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303, 
        0xc009, 0xc00a, 0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f, 
        0xc030, 0xcca8, 0xcca9
    ];
    
    let expected_extensions = vec![
        0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0010, 0x0012, 
        0x0017, 0x001b, 0x001c, 0x0022, 0x0023, 0x002b, 0x002d, 
        0x0033, 0xfe0d, 0xff01
    ];
    
    let expected_sig_algs = vec![
        0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 
        0x0401, 0x0501, 0x0601, 0x0203, 0x0201
    ];

    info!("Expected cipher suites ({}): {:04x?}", expected_ciphers.len(), expected_ciphers);
    info!("Expected extensions ({}): {:04x?}", expected_extensions.len(), expected_extensions);
    info!("Expected signature algorithms ({}): {:04x?}", expected_sig_algs.len(), expected_sig_algs);

    // Create test signature with expected values
    let test_signature = TlsSignature {
        version: TlsVersion::V1_3,
        cipher_suites: expected_ciphers.clone(),
        extensions: expected_extensions.clone(),
        elliptic_curves: vec![],
        elliptic_curve_point_formats: vec![],
        signature_algorithms: expected_sig_algs.clone(),
        sni: Some("example.com".to_string()),
        alpn: Some("h2".to_string()),
    };

    let ja4 = test_signature.generate_ja4();
    
    info!("=== Generated JA4 with expected values ===");
    info!("JA4_a: {}", ja4.ja4_a);
    info!("JA4_b: {}", ja4.ja4_b);
    info!("JA4_c: {}", ja4.ja4_c);
    info!("JA4 hash: {}", ja4.ja4_hash);
    info!("Expected:  t13d1717h2_5b57614c22b0_3cbfd9057e0d");
    
    if ja4.ja4_hash == "t13d1717h2_5b57614c22b0_3cbfd9057e0d" {
        info!("✅ JA4 generation logic is CORRECT!");
    } else {
        info!("❌ JA4 generation logic has issues");
    }

    info!("\n=== Next step: Test with real network traffic ===");
    info!("Run: cargo run --example tls_fingerprint <interface_or_pcap>");
    info!("Look for differences between parsed and expected values");
} 