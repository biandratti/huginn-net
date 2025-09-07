//! HTTPS Analysis Example
//!
//! This example demonstrates the complete HTTPS analysis workflow:
//! - Loading TLS keylog files
//! - Configuring HTTPS analysis
//! - Processing HTTPS traffic with decryption
//! - Extracting HTTP data from encrypted connections

use huginn_net::{AnalysisConfig, HuginnNet};
use std::error::Error;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    // Initialize tracing for better logging
    tracing_subscriber::fmt::init();

    println!("HTTPS Analysis Example");
    println!("=====================");

    // Example 1: Basic HTTPS configuration
    println!("\n--- Basic HTTPS Configuration ---");

    let config = AnalysisConfig {
        http_enabled: true,
        https_enabled: true,
        tcp_enabled: true,
        tls_enabled: true,
        matcher_enabled: false, // Disable for this example
        tls_keylog_files: vec![
            // These would be real keylog files in practice
            PathBuf::from("/tmp/example.com.keylog"),
            PathBuf::from("/tmp/api.example.com.keylog"),
        ],
    };

    println!("Configuration:");
    println!("  HTTP enabled: {}", config.http_enabled);
    println!("  HTTPS enabled: {}", config.https_enabled);
    println!("  TLS enabled: {}", config.tls_enabled);
    println!(
        "  Keylog files: {} configured",
        config.tls_keylog_files.len()
    );

    // Example 2: Create HuginnNet with HTTPS support
    println!("\n--- Creating HuginnNet with HTTPS Support ---");

    // Create temporary keylog files for demonstration
    create_example_keylog_files(&config.tls_keylog_files)?;

    let mut huginn = HuginnNet::new(
        None, // No signature database for this example
        1000, // Max connections
        Some(config),
    );

    println!("HuginnNet initialized:");
    println!("  HTTPS ready: {}", huginn.is_https_ready());

    if let Some((keylog_count, key_count, client_count)) = huginn.https_stats() {
        println!("  Keylog files loaded: {keylog_count}");
        println!("  Total keys available: {key_count}");
        println!("  Unique client sessions: {client_count}");
    }

    // Example 3: Dynamic keylog management
    println!("\n--- Dynamic Keylog Management ---");

    // Create an additional keylog file
    let additional_keylog = "/tmp/cdn.example.com.keylog";
    create_additional_keylog_file(additional_keylog)?;

    // Add it dynamically
    match huginn.add_tls_keylog_file(additional_keylog) {
        Ok(()) => {
            println!("✓ Successfully added additional keylog file");
            if let Some((keylog_count, key_count, client_count)) = huginn.https_stats() {
                println!("  Updated stats - Keylogs: {keylog_count}, Keys: {key_count}, Clients: {client_count}");
            }
        }
        Err(e) => {
            println!("✗ Failed to add keylog file: {e}");
        }
    }

    // Example 4: Configuration scenarios
    println!("\n--- Configuration Scenarios ---");

    // Scenario 1: HTTP only (no HTTPS)
    let http_only_config = AnalysisConfig {
        http_enabled: true,
        https_enabled: false,
        tcp_enabled: true,
        tls_enabled: false,
        matcher_enabled: false,
        tls_keylog_files: Vec::new(),
    };

    let huginn_http_only = HuginnNet::new(None, 1000, Some(http_only_config));
    println!("HTTP-only configuration:");
    println!("  HTTPS ready: {}", huginn_http_only.is_https_ready());

    // Scenario 2: HTTPS without keylog files (TLS fingerprinting only)
    let https_no_keylog_config = AnalysisConfig {
        http_enabled: false,
        https_enabled: true,
        tcp_enabled: true,
        tls_enabled: true,
        matcher_enabled: false,
        tls_keylog_files: Vec::new(),
    };

    let huginn_https_no_keylog = HuginnNet::new(None, 1000, Some(https_no_keylog_config));
    println!("HTTPS without keylog configuration:");
    println!("  HTTPS ready: {}", huginn_https_no_keylog.is_https_ready());

    // Scenario 3: Full analysis (HTTP + HTTPS + TLS + TCP)
    let full_config = AnalysisConfig {
        http_enabled: true,
        https_enabled: true,
        tcp_enabled: true,
        tls_enabled: true,
        matcher_enabled: true,
        tls_keylog_files: vec![
            PathBuf::from("/tmp/example.com.keylog"),
            PathBuf::from("/tmp/api.example.com.keylog"),
        ],
    };

    let huginn_full = HuginnNet::new(None, 1000, Some(full_config));
    println!("Full analysis configuration:");
    println!("  HTTPS ready: {}", huginn_full.is_https_ready());

    // Example 5: Real-world usage patterns
    println!("\n--- Real-world Usage Patterns ---");

    println!("Typical HTTPS analysis workflow:");
    println!("1. Configure browser/application to log TLS keys:");
    println!("   export SSLKEYLOGFILE=/path/to/keylog.txt");
    println!("2. Start your application (browser, curl, etc.)");
    println!("3. Capture network traffic with tcpdump/wireshark");
    println!("4. Use HuginnNet to analyze both traffic and keylog:");

    println!("\n   let config = AnalysisConfig {{");
    println!("       https_enabled: true,");
    println!("       tls_keylog_files: vec![PathBuf::from(\"/path/to/keylog.txt\")],");
    println!("       ..Default::default()");
    println!("   }};");
    println!("   let mut huginn = HuginnNet::new(None, 1000, Some(config));");

    println!("\n5. Process packets:");
    println!("   huginn.process_pcap_file(\"capture.pcap\", sender)?;");

    println!("\n6. Receive results with decrypted HTTP data:");
    println!("   - Original TLS fingerprints (JA4)");
    println!("   - Decrypted HTTP requests/responses");
    println!("   - HTTP header order preservation");
    println!("   - Complete traffic analysis");

    // Example 6: Error handling scenarios
    println!("\n--- Error Handling Scenarios ---");

    // Try to add keylog to HTTP-only configuration
    let mut huginn_http_only_mut = HuginnNet::new(
        None,
        1000,
        Some(AnalysisConfig {
            https_enabled: false,
            ..Default::default()
        }),
    );

    match huginn_http_only_mut.add_tls_keylog_file("/tmp/test.keylog") {
        Ok(()) => println!("✗ Unexpected success"),
        Err(e) => println!("✓ Expected error: {e}"),
    }

    // Try to add non-existent keylog file
    match huginn.add_tls_keylog_file("/non/existent/file.keylog") {
        Ok(()) => println!("✗ Unexpected success"),
        Err(e) => println!("✓ Expected error for non-existent file: {e}"),
    }

    // Cleanup
    cleanup_example_files(&[
        "/tmp/example.com.keylog",
        "/tmp/api.example.com.keylog",
        "/tmp/cdn.example.com.keylog",
    ])?;

    println!("\n--- Summary ---");
    println!("HTTPS Analysis capabilities:");
    println!("  ✓ TLS keylog file management");
    println!("  ✓ Dynamic keylog loading");
    println!("  ✓ Multiple certificate support");
    println!("  ✓ Configuration flexibility");
    println!("  ✓ Error handling");
    println!("  ✓ Statistics and monitoring");
    println!("\nReady for real-world HTTPS traffic analysis!");

    Ok(())
}

/// Create example keylog files for demonstration
fn create_example_keylog_files(paths: &[PathBuf]) -> Result<(), Box<dyn Error>> {
    for (i, path) in paths.iter().enumerate() {
        let content = match i {
            0 => {
                // example.com keylog
                r#"# TLS keylog for example.com
CLIENT_RANDOM 1111111111111111111111111111111111111111111111111111111111111111 fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
CLIENT_TRAFFIC_SECRET_0 1111111111111111111111111111111111111111111111111111111111111111 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
SERVER_TRAFFIC_SECRET_0 1111111111111111111111111111111111111111111111111111111111111111 9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba
"#
            }
            1 => {
                // api.example.com keylog
                r#"# TLS keylog for api.example.com
CLIENT_RANDOM 2222222222222222222222222222222222222222222222222222222222222222 abcdef9876543210abcdef9876543210abcdef9876543210abcdef9876543210
CLIENT_TRAFFIC_SECRET_0 2222222222222222222222222222222222222222222222222222222222222222 fedcba0123456789fedcba0123456789fedcba0123456789fedcba0123456789
SERVER_TRAFFIC_SECRET_0 2222222222222222222222222222222222222222222222222222222222222222 123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0
CLIENT_HANDSHAKE_TRAFFIC_SECRET 2222222222222222222222222222222222222222222222222222222222222222 456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123
"#
            }
            _ => {
                r#"# Default keylog
CLIENT_RANDOM 0000000000000000000000000000000000000000000000000000000000000000 0000000000000000000000000000000000000000000000000000000000000000
"#
            }
        };

        std::fs::write(path, content)?;
    }
    Ok(())
}

/// Create additional keylog file for dynamic loading example
fn create_additional_keylog_file(path: &str) -> Result<(), Box<dyn Error>> {
    let content = r#"# TLS keylog for cdn.example.com
CLIENT_RANDOM 3333333333333333333333333333333333333333333333333333333333333333 cdnkey9876543210cdnkey9876543210cdnkey9876543210cdnkey9876543210
CLIENT_TRAFFIC_SECRET_0 3333333333333333333333333333333333333333333333333333333333333333 cdnsec0123456789cdnsec0123456789cdnsec0123456789cdnsec0123456789
SERVER_TRAFFIC_SECRET_0 3333333333333333333333333333333333333333333333333333333333333333 cdnser789abcdef0cdnser789abcdef0cdnser789abcdef0cdnser789abcdef0
"#;

    std::fs::write(path, content)?;
    Ok(())
}

/// Cleanup example files
fn cleanup_example_files(paths: &[&str]) -> Result<(), Box<dyn Error>> {
    for path in paths {
        if std::path::Path::new(path).exists() {
            std::fs::remove_file(path)?;
        }
    }
    Ok(())
}
