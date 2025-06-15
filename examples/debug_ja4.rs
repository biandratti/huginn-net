use passivetcp_rs::tls::{TlsSignature, TlsVersion};

fn main() {
    // Test case based on the expected ja4_fingerprint_string
    // "t13d1717h2_002f,0035,009c,009d,1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0023,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201"
    
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
    
    let signature = TlsSignature {
        version: TlsVersion::V1_3,
        cipher_suites: expected_ciphers,
        extensions: expected_extensions,
        elliptic_curves: vec![],
        elliptic_curve_point_formats: vec![],
        signature_algorithms: expected_sig_algs,
        sni: Some("example.com".to_string()),
        alpn: Some("h2".to_string()),
    };

    let ja4 = signature.generate_ja4();
    
    println!("Generated JA4: {}", ja4.ja4_hash);
    println!("Expected JA4:  t13d1717h2_5b57614c22b0_3cbfd9057e0d");
    println!();
    println!("JA4_a: {}", ja4.ja4_a);
    println!("JA4_b: {}", ja4.ja4_b);
    println!("JA4_c: {}", ja4.ja4_c);
    println!();
    println!("Raw fingerprint: {}", ja4.ja4_full);
    
    // Check if they match
    if ja4.ja4_hash == "t13d1717h2_5b57614c22b0_3cbfd9057e0d" {
        println!("✅ JA4 matches expected value!");
    } else {
        println!("❌ JA4 does not match expected value");
    }
} 