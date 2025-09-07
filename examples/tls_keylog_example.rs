use huginn_net::tls_keylog::{KeyType, TlsKeylog, TlsKeylogManager};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("TLS Keylog Parser Example");
    println!("========================");

    // Example 1: Single keylog
    println!("\n--- Single Keylog Example ---");

    // Example keylog content (what you'd typically find in SSLKEYLOGFILE)
    let example_keylog = r#"
# NSS Key Log Format 1.0
# This is a generated file! Do not edit.

CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
CLIENT_TRAFFIC_SECRET_0 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
SERVER_TRAFFIC_SECRET_0 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01

# Another session
CLIENT_RANDOM abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba
CLIENT_HANDSHAKE_TRAFFIC_SECRET abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876
"#;

    // Parse the keylog
    let keylog = TlsKeylog::from_string(example_keylog)?;

    println!("Loaded keylog:");
    println!("  Total keys: {}", keylog.key_count());
    println!("  Unique sessions: {}", keylog.client_count());
    println!();

    // Example: Find keys for a specific client random
    let client_random =
        hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")?;

    if let Some(keys) = keylog.find_keys(&client_random) {
        println!(
            "Found {} keys for client random: {}",
            keys.len(),
            hex::encode(&client_random)
        );

        for key in keys {
            println!("  Key type: {:?}", key.key_type);
            println!("  Key data length: {} bytes", key.key_data.len());
            println!(
                "  Key data: {}...",
                hex::encode(&key.key_data[..8.min(key.key_data.len())])
            );
            println!();
        }
    }

    // Example: Find specific key type
    if let Some(master_secret) = keylog.find_key_by_type(&client_random, &KeyType::ClientRandom) {
        println!("Found TLS 1.2 master secret:");
        println!("  Length: {} bytes", master_secret.key_data.len());
        println!(
            "  Data: {}...",
            hex::encode(&master_secret.key_data[..16.min(master_secret.key_data.len())])
        );
        println!();
    }

    if let Some(traffic_secret) =
        keylog.find_key_by_type(&client_random, &KeyType::ClientTrafficSecret0)
    {
        println!("Found TLS 1.3 client traffic secret:");
        println!("  Length: {} bytes", traffic_secret.key_data.len());
        println!(
            "  Data: {}...",
            hex::encode(&traffic_secret.key_data[..16.min(traffic_secret.key_data.len())])
        );
        println!();
    }

    // Example 2: Multiple keylogs with manager
    println!("\n--- Multiple Keylogs Manager Example ---");

    let keylog1 = r#"
# example.com keylog
CLIENT_RANDOM 1111111111111111111111111111111111111111111111111111111111111111 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
CLIENT_TRAFFIC_SECRET_0 1111111111111111111111111111111111111111111111111111111111111111 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
"#;

    let keylog2 = r#"
# api.example.com keylog  
CLIENT_RANDOM 2222222222222222222222222222222222222222222222222222222222222222 cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
SERVER_TRAFFIC_SECRET_0 2222222222222222222222222222222222222222222222222222222222222222 dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
"#;

    let keylog3 = r#"
# cdn.example.com keylog
CLIENT_RANDOM 3333333333333333333333333333333333333333333333333333333333333333 eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
CLIENT_HANDSHAKE_TRAFFIC_SECRET 3333333333333333333333333333333333333333333333333333333333333333 ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
"#;

    // Create manager and load multiple keylogs
    let mut manager = TlsKeylogManager::new();
    manager.add_keylog_from_string("example.com".to_string(), keylog1)?;
    manager.add_keylog_from_string("api.example.com".to_string(), keylog2)?;
    manager.add_keylog_from_string("cdn.example.com".to_string(), keylog3)?;

    println!("Loaded keylog manager:");
    println!("  Total keylog files: {}", manager.keylog_count());
    println!("  Total keys: {}", manager.total_key_count());
    println!("  Total sessions: {}", manager.total_client_count());
    println!();

    // Show info for each keylog
    for (name, key_count, client_count) in manager.keylog_info() {
        println!("  {name}: {key_count} keys, {client_count} sessions");
    }
    println!();

    // Find keys across multiple keylogs
    let client_random1 =
        hex::decode("1111111111111111111111111111111111111111111111111111111111111111")?;
    let client_random2 =
        hex::decode("2222222222222222222222222222222222222222222222222222222222222222")?;
    let client_random3 =
        hex::decode("3333333333333333333333333333333333333333333333333333333333333333")?;

    // Test finding keys from different keylogs
    if let Some((source, keys)) = manager.find_keys(&client_random1) {
        println!(
            "Found {} keys for session 1 in keylog: {}",
            keys.len(),
            source
        );
    }

    if let Some((source, keys)) = manager.find_keys(&client_random2) {
        println!(
            "Found {} keys for session 2 in keylog: {}",
            keys.len(),
            source
        );
    }

    if let Some((source, keys)) = manager.find_keys(&client_random3) {
        println!(
            "Found {} keys for session 3 in keylog: {}",
            keys.len(),
            source
        );
    }
    println!();

    // Find specific key types across keylogs
    if let Some((source, _key)) =
        manager.find_key_by_type(&client_random1, &KeyType::ClientTrafficSecret0)
    {
        println!("Found TLS 1.3 client traffic secret for session 1 in: {source}");
    }

    if let Some((source, _key)) =
        manager.find_key_by_type(&client_random2, &KeyType::ServerTrafficSecret0)
    {
        println!("Found TLS 1.3 server traffic secret for session 2 in: {source}");
    }

    if let Some((source, _key)) =
        manager.find_key_by_type(&client_random3, &KeyType::ClientHandshakeTrafficSecret)
    {
        println!("Found TLS 1.3 handshake secret for session 3 in: {source}");
    }
    println!();

    println!("Multi-keylog example completed successfully!");
    println!("\nThis demonstrates how to handle multiple certificates/domains");
    println!("in a network where you might have:");
    println!("  - example.com (main site)");
    println!("  - api.example.com (API server)");
    println!("  - cdn.example.com (CDN/static assets)");
    println!("Each with their own TLS certificates and keylog files.");

    Ok(())
}
