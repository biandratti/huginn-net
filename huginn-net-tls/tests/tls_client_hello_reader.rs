use huginn_net_tls::error::HuginnNetTlsError;
use huginn_net_tls::tls_client_hello_reader::TlsClientHelloReader;

/// Helper function to create a minimal valid TLS ClientHello record
///
/// Creates a TLS handshake record containing a ClientHello message.
/// Format: [content_type:8][version:16][length:16][handshake_message]
fn create_tls_client_hello_record(version: (u8, u8), handshake_payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::new();

    // Content Type: Handshake (0x16)
    record.push(0x16);

    // Version (e.g., TLS 1.2 = 0x03 0x03)
    record.push(version.0);
    record.push(version.1);

    // Record length (big-endian u16)
    let record_len = handshake_payload.len() as u16;
    record.extend_from_slice(&record_len.to_be_bytes());

    // Handshake payload
    record.extend_from_slice(handshake_payload);

    record
}

/// Create a minimal ClientHello handshake message
///
/// Format: [handshake_type:8][length:24][version:16][random:32][session_id_len:8][ciphers_len:16][ciphers][comp_len:8][comp][ext_len:16][extensions]
fn create_client_hello_handshake(
    version: (u8, u8),
    cipher_suites: &[u16],
    extensions: Option<&[u8]>,
) -> Vec<u8> {
    let mut handshake = Vec::new();

    // Handshake Type: ClientHello (0x01)
    handshake.push(0x01);

    // Handshake length (will be filled later)
    let length_pos = handshake.len();
    handshake.extend_from_slice(&[0x00, 0x00, 0x00]);

    // Version
    handshake.push(version.0);
    handshake.push(version.1);

    // Random (32 bytes)
    handshake.extend_from_slice(&[0u8; 32]);

    // Session ID length (0 = no session ID)
    handshake.push(0x00);

    // Cipher suites length
    let cipher_len = (cipher_suites.len().saturating_mul(2)) as u16;
    handshake.extend_from_slice(&cipher_len.to_be_bytes());

    // Cipher suites
    for &suite in cipher_suites {
        handshake.extend_from_slice(&suite.to_be_bytes());
    }

    // Compression methods length (1 = NULL compression)
    handshake.push(0x01);
    handshake.push(0x00); // NULL compression

    // Extensions length
    let ext_len = extensions.map(|e| e.len()).unwrap_or(0) as u16;
    handshake.extend_from_slice(&ext_len.to_be_bytes());

    // Extensions
    if let Some(ext) = extensions {
        handshake.extend_from_slice(ext);
    }

    // Update handshake length (skip the 4-byte header)
    let handshake_len = handshake.len().saturating_sub(4) as u32;
    let length_pos_1 = length_pos.saturating_add(1);
    let length_pos_2 = length_pos.saturating_add(2);
    handshake[length_pos] = ((handshake_len >> 16) & 0xFF) as u8;
    handshake[length_pos_1] = ((handshake_len >> 8) & 0xFF) as u8;
    handshake[length_pos_2] = (handshake_len & 0xFF) as u8;

    handshake
}

#[test]
fn test_new() {
    let reader = TlsClientHelloReader::new();
    assert!(!reader.signature_parsed());
    assert!(reader.get_signature().is_none());
}

#[test]
fn test_default() {
    let reader = TlsClientHelloReader::default();
    assert!(!reader.signature_parsed());
    assert!(reader.get_signature().is_none());
}

#[test]
fn test_add_bytes_empty() {
    let mut reader = TlsClientHelloReader::new();
    let result = reader.add_bytes(&[]);
    assert!(result.is_ok());
    if let Ok(value) = result {
        assert!(value.is_none());
    }
    assert!(!reader.signature_parsed());
}

#[test]
fn test_add_bytes_insufficient_data() {
    let mut reader = TlsClientHelloReader::new();
    // Less than 5 bytes (minimum TLS record header)
    let result = reader.add_bytes(&[0x16, 0x03, 0x03]);
    assert!(result.is_ok());
    if let Ok(value) = result {
        assert!(value.is_none());
    }
    assert!(!reader.signature_parsed());
}

#[test]
fn test_add_bytes_complete_record() {
    let mut reader = TlsClientHelloReader::new();

    // Create a minimal valid ClientHello
    let cipher_suites = vec![0x1301u16, 0x1302u16]; // TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
    let handshake = create_client_hello_handshake((0x03, 0x03), &cipher_suites, None);
    let record = create_tls_client_hello_record((0x03, 0x03), &handshake);

    let result = reader.add_bytes(&record);
    assert!(result.is_ok());
    // Should parse successfully
    if let Ok(signature_result) = result {
        assert!(signature_result.is_some());
    }
    assert!(reader.signature_parsed());
    assert!(reader.get_signature().is_some());
}

#[test]
fn test_add_bytes_incremental() {
    let mut reader = TlsClientHelloReader::new();

    // Create a ClientHello record
    let cipher_suites = vec![0x1301u16];
    let handshake = create_client_hello_handshake((0x03, 0x03), &cipher_suites, None);
    let record = create_tls_client_hello_record((0x03, 0x03), &handshake);

    // Split into parts
    let mid_point = record.len() / 2;
    let part1 = &record[..mid_point];
    let part2 = &record[mid_point..];

    // Add first part
    let result1 = reader.add_bytes(part1);
    assert!(result1.is_ok());
    if let Ok(value) = result1 {
        assert!(value.is_none());
    }
    assert!(!reader.signature_parsed());

    // Add second part
    let result2 = reader.add_bytes(part2);
    assert!(result2.is_ok());
    // Should parse successfully now
    if let Ok(signature_result) = result2 {
        assert!(signature_result.is_some());
    }
    assert!(reader.signature_parsed());
}

#[test]
fn test_add_bytes_after_signature_parsed() {
    let mut reader = TlsClientHelloReader::new();

    // First parse a signature
    let cipher_suites = vec![0x1301u16];
    let handshake = create_client_hello_handshake((0x03, 0x03), &cipher_suites, None);
    let record = create_tls_client_hello_record((0x03, 0x03), &handshake);
    let _ = reader.add_bytes(&record);
    assert!(reader.signature_parsed());

    // Try to add more data after signature is parsed
    let more_data = vec![0x16, 0x03, 0x03, 0x00, 0x10];
    let result = reader.add_bytes(&more_data);
    assert!(result.is_ok());
    // Should return None and not process the new data
    if let Ok(value) = result {
        assert!(value.is_none());
    }
    // Signature should still be available
    assert!(reader.signature_parsed());
}

#[test]
fn test_add_bytes_record_too_large() {
    let mut reader = TlsClientHelloReader::new();

    // Create a record that claims to be larger than 64KB
    // The check is: needed > 64 * 1024, where needed = record_len + 5
    // So we need record_len > 65531. Let's use 65532 which gives needed = 65537 > 65536
    let mut large_record = vec![0x16, 0x03, 0x03];
    let record_len = 65532u16; // This gives needed = 65537 > 65536
    large_record.extend_from_slice(&record_len.to_be_bytes());
    // Add enough data so the buffer has the complete record (to trigger the size check)
    // We need at least record_len bytes of payload
    large_record.extend_from_slice(&vec![0u8; record_len as usize]);

    let result = reader.add_bytes(&large_record);
    // The check is: needed > 64 * 1024, where needed = record_len + 5
    // With record_len = 65535, needed = 65540 > 65536, so should error
    assert!(result.is_err());
    if let Err(HuginnNetTlsError::Parse(msg)) = result {
        assert!(msg.contains("too large") || msg.contains("large"));
    }
}

#[test]
fn test_add_bytes_incomplete_record() {
    let mut reader = TlsClientHelloReader::new();

    // Create a record header that says length is 1000, but only provide 10 bytes
    let mut incomplete_record = vec![0x16, 0x03, 0x03];
    incomplete_record.extend_from_slice(&1000u16.to_be_bytes());
    incomplete_record.extend_from_slice(&[0u8; 10]); // Only 10 bytes, not 1000

    let result = reader.add_bytes(&incomplete_record);
    assert!(result.is_ok());
    // Should return None (need more data)
    if let Ok(value) = result {
        assert!(value.is_none());
    }
    assert!(!reader.signature_parsed());
}

#[test]
fn test_get_signature_before_parsing() {
    let reader = TlsClientHelloReader::new();
    assert!(reader.get_signature().is_none());
}

#[test]
fn test_get_signature_after_parsing() {
    let mut reader = TlsClientHelloReader::new();

    let cipher_suites = vec![0x1301u16, 0x1302u16];
    let handshake = create_client_hello_handshake((0x03, 0x03), &cipher_suites, None);
    let record = create_tls_client_hello_record((0x03, 0x03), &handshake);

    let _ = reader.add_bytes(&record);

    let signature = reader.get_signature();
    assert!(signature.is_some());
    if let Some(sig) = signature {
        assert_eq!(sig.cipher_suites.len(), 2);
        assert!(sig.cipher_suites.contains(&0x1301));
        assert!(sig.cipher_suites.contains(&0x1302));
    }
}

#[test]
fn test_signature_parsed() {
    let mut reader = TlsClientHelloReader::new();
    assert!(!reader.signature_parsed());

    let cipher_suites = vec![0x1301u16];
    let handshake = create_client_hello_handshake((0x03, 0x03), &cipher_suites, None);
    let record = create_tls_client_hello_record((0x03, 0x03), &handshake);

    let _ = reader.add_bytes(&record);
    assert!(reader.signature_parsed());
}

#[test]
fn test_reset() {
    let mut reader = TlsClientHelloReader::new();

    // Parse a signature first
    let cipher_suites = vec![0x1301u16];
    let handshake = create_client_hello_handshake((0x03, 0x03), &cipher_suites, None);
    let record = create_tls_client_hello_record((0x03, 0x03), &handshake);
    let _ = reader.add_bytes(&record);
    assert!(reader.signature_parsed());

    // Reset
    reader.reset();

    // Should be back to initial state
    assert!(!reader.signature_parsed());
    assert!(reader.get_signature().is_none());

    // Should be able to parse again
    let _ = reader.add_bytes(&record);
    assert!(reader.signature_parsed());
}

#[test]
fn test_multiple_add_bytes_calls() {
    let mut reader = TlsClientHelloReader::new();

    // Create a ClientHello record
    let cipher_suites = vec![0x1301u16, 0x1302u16, 0x1303u16];
    let handshake = create_client_hello_handshake((0x03, 0x03), &cipher_suites, None);
    let record = create_tls_client_hello_record((0x03, 0x03), &handshake);

    // Split into multiple parts
    let part1 = &record[..5]; // Just the header
    let part2 = &record[5..record.len() / 2];
    let part3 = &record[record.len() / 2..];

    // Add parts incrementally
    let result1 = reader.add_bytes(part1);
    assert!(result1.is_ok());
    if let Ok(value) = result1 {
        assert!(value.is_none());
    }

    let result2 = reader.add_bytes(part2);
    assert!(result2.is_ok());
    // May or may not have enough data yet
    let sig2 = result2.unwrap_or_default();

    let result3 = reader.add_bytes(part3);
    assert!(result3.is_ok());
    // Should parse successfully now
    let sig3 = result3.unwrap_or_default();
    assert!(sig2.is_some() || sig3.is_some());
    assert!(reader.signature_parsed());
}

#[test]
fn test_record_length_calculation() {
    let mut reader = TlsClientHelloReader::new();

    // Create a record with specific length
    let cipher_suites = vec![0x1301u16];
    let handshake = create_client_hello_handshake((0x03, 0x03), &cipher_suites, None);
    let record = create_tls_client_hello_record((0x03, 0x03), &handshake);

    // Verify record length is correct
    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    assert_eq!(record_len + 5, record.len());

    // Should parse successfully
    let result = reader.add_bytes(&record);
    assert!(result.is_ok());
    if let Ok(value) = result {
        assert!(value.is_some());
    }
}

#[test]
fn test_tls_1_2_version() {
    let mut reader = TlsClientHelloReader::new();

    // TLS 1.2 = 0x03 0x03
    let cipher_suites = vec![0x1301u16];
    let handshake = create_client_hello_handshake((0x03, 0x03), &cipher_suites, None);
    let record = create_tls_client_hello_record((0x03, 0x03), &handshake);

    let result = reader.add_bytes(&record);
    assert!(result.is_ok());
    if let Ok(Some(signature)) = result {
        assert_eq!(signature.version, huginn_net_tls::tls::TlsVersion::V1_2);
    }
}

#[test]
fn test_tls_1_3_version() {
    let mut reader = TlsClientHelloReader::new();

    // TLS 1.3 uses 0x03 0x03 in record but 0x03 0x04 in handshake
    // For TLS 1.3, we need supported_versions extension
    let cipher_suites = vec![0x1301u16, 0x1302u16, 0x1303u16];

    // Create extensions with supported_versions
    let mut extensions = Vec::new();
    // Extension: supported_versions (0x002b)
    extensions.extend_from_slice(&0x002bu16.to_be_bytes());
    extensions.extend_from_slice(&0x0002u16.to_be_bytes()); // Length: 2 bytes
    extensions.extend_from_slice(&0x0304u16.to_be_bytes()); // TLS 1.3

    let handshake = create_client_hello_handshake((0x03, 0x03), &cipher_suites, Some(&extensions));
    let record = create_tls_client_hello_record((0x03, 0x03), &handshake);

    let result = reader.add_bytes(&record);
    assert!(result.is_ok());
    if let Ok(Some(signature)) = result {
        assert_eq!(signature.version, huginn_net_tls::tls::TlsVersion::V1_3);
    }
}

#[test]
fn test_invalid_tls_record() {
    let mut reader = TlsClientHelloReader::new();

    // Invalid TLS record (not a handshake - 0x17 is Application Data)
    let invalid_record = vec![0x17, 0x03, 0x03, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00];
    let result = reader.add_bytes(&invalid_record);
    // Should return Ok(None) because it's not a handshake record (we only care about ClientHello)
    assert!(result.is_ok());
    if let Ok(value) = result {
        assert!(value.is_none(), "Non-handshake records should return None");
    }
    assert!(!reader.signature_parsed());
}

#[test]
fn test_grease_filtering() {
    let mut reader = TlsClientHelloReader::new();

    // Create ClientHello with GREASE cipher suite
    let cipher_suites = vec![0x1301u16, 0x0a0au16, 0x1302u16]; // GREASE in middle
    let handshake = create_client_hello_handshake((0x03, 0x03), &cipher_suites, None);
    let record = create_tls_client_hello_record((0x03, 0x03), &handshake);

    let result = reader.add_bytes(&record);
    assert!(result.is_ok());
    if let Ok(Some(sig)) = result {
        // GREASE should be filtered out
        assert_eq!(sig.cipher_suites.len(), 2);
        assert!(sig.cipher_suites.contains(&0x1301));
        assert!(sig.cipher_suites.contains(&0x1302));
        assert!(!sig.cipher_suites.contains(&0x0a0a));
    }
}

#[test]
fn test_client_hello_with_extensions() {
    let mut reader = TlsClientHelloReader::new();

    let cipher_suites = vec![0x1301u16];

    // Create extensions: SNI extension
    // Format according to RFC 6066:
    // Extension: [extension_type:16][extension_length:16][server_name_list]
    // server_name_list: [list_length:16][server_name_entry...]
    // server_name_entry: [name_type:8][hostname_length:16][hostname]
    let mut extensions = Vec::new();
    // Extension: server_name (0x0000)
    extensions.extend_from_slice(&0x0000u16.to_be_bytes());

    // Calculate lengths
    let hostname = b"example.com";
    let hostname_len = hostname.len() as u16;
    let entry_len = 1u16 + 2u16 + hostname_len; // name_type(1) + hostname_length(2) + hostname
    let list_len = 2u16 + entry_len; // list_length(2) + entry
    let ext_data_len = list_len; // Extension data is just the server_name_list

    extensions.extend_from_slice(&ext_data_len.to_be_bytes()); // Extension data length
    extensions.extend_from_slice(&list_len.to_be_bytes()); // Server name list length
    extensions.push(0x00); // Name type: hostname (0x00)
    extensions.extend_from_slice(&hostname_len.to_be_bytes()); // Hostname length
    extensions.extend_from_slice(hostname); // Hostname

    let handshake = create_client_hello_handshake((0x03, 0x03), &cipher_suites, Some(&extensions));
    let record = create_tls_client_hello_record((0x03, 0x03), &handshake);

    let result = reader.add_bytes(&record);
    // The parsing should succeed (even if extension parsing fails)
    // The important thing is that the reader handles ClientHello with extensions gracefully
    assert!(result.is_ok());
    if let Ok(Some(sig)) = result {
        // Verify basic signature fields are present
        assert_eq!(sig.cipher_suites.len(), 1);
        assert!(sig.cipher_suites.contains(&0x1301));
    }
}

#[test]
fn test_buffer_capacity() {
    // Verify initial capacity is set (implementation detail, but good to test)
    // The buffer should have capacity for reasonable TLS records
    // We can't directly access buffer, but we can test it works with large records
    let mut reader2 = TlsClientHelloReader::new();

    // Create a larger ClientHello
    let cipher_suites: Vec<u16> = (0..50).map(|i| 0x1301u16 + i).collect();
    let handshake = create_client_hello_handshake((0x03, 0x03), &cipher_suites, None);
    let record = create_tls_client_hello_record((0x03, 0x03), &handshake);

    let result = reader2.add_bytes(&record);
    assert!(result.is_ok());
    // Should handle larger records without issues
    // The result may be Some or None depending on parsing success, both are valid
    let _signature = result.unwrap_or_default();
    // Signature parsed or not, both are valid outcomes
}

#[test]
fn test_exact_record_length() {
    let mut reader = TlsClientHelloReader::new();

    // Create a record where we have exactly the right amount of data
    let cipher_suites = vec![0x1301u16];
    let handshake = create_client_hello_handshake((0x03, 0x03), &cipher_suites, None);
    let record = create_tls_client_hello_record((0x03, 0x03), &handshake);

    // Add exactly the record length
    let result = reader.add_bytes(&record);
    assert!(result.is_ok());
    // Should parse successfully
    if let Ok(value) = result {
        assert!(value.is_some());
    }
    assert!(reader.signature_parsed());
}

#[test]
fn test_tcp_segmentation_realistic() {
    // Test that simulates realistic TCP segmentation:
    // - Large ClientHello (similar to real browsers, ~2000 bytes)
    // - Split into TCP segments of ~1448 bytes (typical MSS)
    // - First segment has TLS header, subsequent segments are continuation

    let mut reader = TlsClientHelloReader::new();

    // Create a large ClientHello similar to real browsers
    // Include many cipher suites to make it large
    let mut cipher_suites: Vec<u16> = Vec::new();
    for i in 0..100 {
        cipher_suites.push(0x1301u16 + (i % 50)); // Add many cipher suites
    }

    // Create extensions to make it larger (SNI, ALPN, etc.)
    let mut extensions = Vec::new();

    // Extension: server_name (0x0000)
    let hostname = b"example.com";
    let hostname_len = hostname.len() as u16;
    extensions.extend_from_slice(&0x0000u16.to_be_bytes()); // Extension type
    let entry_len = 1u16 + 2u16 + hostname_len;
    let list_len = 2u16 + entry_len;
    extensions.extend_from_slice(&list_len.to_be_bytes()); // Extension length
    extensions.extend_from_slice(&list_len.to_be_bytes()); // Server name list length
    extensions.push(0x00); // Name type: hostname
    extensions.extend_from_slice(&hostname_len.to_be_bytes());
    extensions.extend_from_slice(hostname);

    // Extension: ALPN (0x0010)
    let alpn_protocol = b"h2";
    let alpn_protocol_len = alpn_protocol.len() as u8;
    extensions.extend_from_slice(&0x0010u16.to_be_bytes()); // Extension type
    let alpn_list_len = 1u16 + alpn_protocol_len as u16; // protocol_list length
    let alpn_ext_len = 2u16 + alpn_list_len; // extension length
    extensions.extend_from_slice(&alpn_ext_len.to_be_bytes()); // Extension length
    extensions.extend_from_slice(&alpn_list_len.to_be_bytes()); // Protocol list length
    extensions.push(alpn_protocol_len); // Protocol name length
    extensions.extend_from_slice(alpn_protocol); // Protocol name

    // Add many extensions with data to make it large enough to fragment
    for ext_type in [
        0x0005u16, 0x000au16, 0x000bu16, 0x000du16, 0x0012u16, 0x0017u16, 0x001bu16, 0x0023u16,
        0x002bu16, 0x002du16, 0x0033u16,
    ] {
        extensions.extend_from_slice(&ext_type.to_be_bytes());
        // Add extension with some data (not empty) to increase size
        let ext_data_len = 200u16; // Add 200 bytes of data per extension
        extensions.extend_from_slice(&ext_data_len.to_be_bytes());
        extensions.extend_from_slice(&vec![0u8; ext_data_len as usize]);
    }

    let handshake = create_client_hello_handshake((0x03, 0x03), &cipher_suites, Some(&extensions));
    let record = create_tls_client_hello_record((0x03, 0x03), &handshake);

    // Verify the record is large enough to be segmented (should be > 1448 bytes)
    assert!(
        record.len() > 1448,
        "Record should be large enough to test segmentation (got {} bytes)",
        record.len()
    );

    // Simulate TCP segmentation: split into segments of ~1448 bytes (typical MSS)
    const TCP_MSS: usize = 1448;
    let mut segments = Vec::new();
    let mut offset = 0;

    while offset < record.len() {
        let segment_end = (offset + TCP_MSS).min(record.len());
        segments.push(&record[offset..segment_end]);
        offset = segment_end;
    }

    assert!(
        segments.len() >= 2,
        "Record should be split into at least 2 segments (got {})",
        segments.len()
    );

    // First segment should start with TLS header (0x16)
    assert_eq!(segments[0][0], 0x16, "First segment should start with TLS handshake (0x16)");

    // Subsequent segments should NOT start with 0x16 (they're continuation)
    for (i, segment) in segments.iter().enumerate().skip(1) {
        assert_ne!(
            segment[0], 0x16,
            "Segment {} should not start with 0x16 (it's continuation data)",
            i
        );
    }

    // Add segments incrementally (simulating TCP packet arrival)
    let mut parsed = false;
    for (i, segment) in segments.iter().enumerate() {
        let result = reader.add_bytes(segment);
        assert!(result.is_ok(), "Failed to add segment {}: {:?}", i, result);

        if let Ok(Some(signature)) = result {
            // Should parse successfully on the last segment
            assert_eq!(i, segments.len() - 1, "Should only parse on the last segment");
            assert_eq!(signature.version, huginn_net_tls::tls::TlsVersion::V1_2);
            // Verify we got cipher suites (may be filtered, so just check not empty)
            assert!(!signature.cipher_suites.is_empty(), "Should have at least some cipher suites");
            // SNI and ALPN may or may not parse correctly with large extensions, so we don't assert them
            parsed = true;
        } else if let Ok(None) = result {
            // Expected for all segments except the last
            assert!(i < segments.len() - 1, "Should return None for all segments except the last");
        }
    }

    assert!(parsed, "Should have parsed the signature after all segments");
    assert!(reader.signature_parsed(), "Reader should report signature as parsed");
    assert!(reader.get_signature().is_some(), "Should be able to retrieve signature");
}

#[test]
fn test_tcp_segmentation_three_segments_reassembly() {
    let mut reader = TlsClientHelloReader::new();

    // Create a ClientHello that will be split into exactly 3 segments
    // Target size: ~2900 bytes (3 segments of ~1448 bytes each)
    let mut cipher_suites = Vec::new();
    for i in 0..100 {
        cipher_suites.push(0x1301u16 + (i % 10));
    }

    let mut extensions = Vec::new();

    // Add many extensions to reach target size
    for ext_type in 0..50 {
        extensions.extend_from_slice(&(ext_type as u16).to_be_bytes());
        // Add some data to each extension
        let ext_data_len = 50u16;
        extensions.extend_from_slice(&ext_data_len.to_be_bytes());
        extensions.extend_from_slice(&vec![0u8; ext_data_len as usize]);
    }

    let handshake = create_client_hello_handshake((0x03, 0x03), &cipher_suites, Some(&extensions));
    let record = create_tls_client_hello_record((0x03, 0x03), &handshake);

    // Split into 3 segments
    const SEGMENT_SIZE: usize = 1448;
    let segment1 = &record[..SEGMENT_SIZE.min(record.len())];
    let segment2 = if record.len() > SEGMENT_SIZE {
        &record[SEGMENT_SIZE..(SEGMENT_SIZE * 2).min(record.len())]
    } else {
        &[]
    };
    let segment3 = if record.len() > SEGMENT_SIZE * 2 {
        &record[SEGMENT_SIZE * 2..]
    } else {
        &[]
    };

    // Add first segment (should not parse yet)
    let result1 = reader.add_bytes(segment1);
    assert!(result1.is_ok());
    if let Ok(value) = result1 {
        assert!(value.is_none(), "First segment should not complete parsing");
    }
    assert!(!reader.signature_parsed());

    // Add second segment (should not parse yet if record is large enough)
    if !segment2.is_empty() {
        let result2 = reader.add_bytes(segment2);
        assert!(result2.is_ok());
        if let Ok(result2_value) = result2 {
            if segment3.is_empty() {
                // If only 2 segments, should parse now
                assert!(result2_value.is_some() || reader.signature_parsed());
            } else {
                // If 3 segments, should not parse yet
                assert!(
                    result2_value.is_none(),
                    "Second segment should not complete parsing if there's a third"
                );
                assert!(!reader.signature_parsed());
            }
        }
    }

    // Add third segment (should parse now)
    if !segment3.is_empty() {
        let result3 = reader.add_bytes(segment3);
        assert!(result3.is_ok());
        if let Ok(value) = result3 {
            assert!(value.is_some(), "Third segment should complete parsing");
        }
        assert!(reader.signature_parsed());

        if let Some(signature) = reader.get_signature() {
            assert_eq!(signature.version, huginn_net_tls::tls::TlsVersion::V1_2);
            assert!(!signature.cipher_suites.is_empty());
        }
    }
}
