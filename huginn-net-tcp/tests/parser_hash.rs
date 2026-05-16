use huginn_net_tcp::packet_hash::*;

#[test]
fn test_hash_ipv4_source_ip() {
    // Ethernet + IPv4 packet
    let mut packet = vec![0u8; 34];

    // Ethernet header
    packet[12] = 0x08; // IPv4 EtherType
    packet[13] = 0x00;

    // IPv4 header (starts at byte 14)
    packet[14] = 0x45; // Version 4, IHL 5

    // Source IP: 192.168.1.1
    packet[26] = 192;
    packet[27] = 168;
    packet[28] = 1;
    packet[29] = 1;

    // Dest IP: 10.0.0.1
    packet[30] = 10;
    packet[31] = 0;
    packet[32] = 0;
    packet[33] = 1;

    let hash1 = hash_source_ip(&packet);
    let hash2 = hash_source_ip(&packet);

    // Same packet should always produce same hash
    assert_eq!(hash1, hash2);
}

#[test]
fn test_hash_ipv4_different_sources() {
    let mut packet1 = vec![0u8; 34];
    let mut packet2 = vec![0u8; 34];

    // Setup both as valid IPv4 packets
    for packet in [&mut packet1, &mut packet2] {
        packet[12] = 0x08;
        packet[13] = 0x00;
        packet[14] = 0x45;
    }

    // Packet 1: 192.168.1.1
    packet1[26..30].copy_from_slice(&[192, 168, 1, 1]);
    packet1[30..34].copy_from_slice(&[10, 0, 0, 1]);

    // Packet 2: 192.168.1.2 (different source IP)
    packet2[26..30].copy_from_slice(&[192, 168, 1, 2]);
    packet2[30..34].copy_from_slice(&[10, 0, 0, 1]);

    let hash1 = hash_source_ip(&packet1);
    let hash2 = hash_source_ip(&packet2);

    // Different source IPs should produce different hashes
    // (not guaranteed, but very likely with good hash function)
    assert_ne!(hash1, hash2);
}

#[test]
fn test_hash_ipv6_source_ip() {
    let mut packet = vec![0u8; 54];

    // Ethernet header
    packet[12] = 0x86; // IPv6 EtherType
    packet[13] = 0xDD;

    // IPv6 header (starts at byte 14)
    packet[14] = 0x60; // Version 6

    // Source IP (16 bytes starting at byte 22)
    packet[22..38].copy_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ]);

    // Dest IP (16 bytes)
    packet[38..54].copy_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ]);

    let hash1 = hash_source_ip(&packet);
    let hash2 = hash_source_ip(&packet);

    assert_eq!(hash1, hash2);
}

#[test]
fn test_hash_ipv6_different_sources() {
    let mut packet1 = vec![0u8; 54];
    let mut packet2 = vec![0u8; 54];

    // Setup both as valid IPv6 packets
    for packet in [&mut packet1, &mut packet2] {
        packet[12] = 0x86;
        packet[13] = 0xDD;
        packet[14] = 0x60;
    }

    // Packet 1: 2001:db8::1
    packet1[22..38].copy_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ]);

    // Packet 2: 2001:db8::2 (different source IP)
    packet2[22..38].copy_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ]);

    let hash1 = hash_source_ip(&packet1);
    let hash2 = hash_source_ip(&packet2);

    // Different source IPs should produce different hashes
    assert_ne!(hash1, hash2);
}

#[test]
fn test_hash_fallback_on_short_packet() {
    let short_packet = vec![0u8; 10];

    // Should not panic, should use fallback hash
    let hash = hash_source_ip(&short_packet);

    // Verify hash is consistent
    assert_eq!(hash, hash_source_ip(&short_packet));
}

#[test]
fn test_hash_fallback_on_invalid_ip_version() {
    let mut packet = vec![0u8; 40];
    packet[12] = 0x08;
    packet[13] = 0x00;
    packet[14] = 0x75; // Invalid IP version (7)

    // Should not panic, should use fallback hash
    let hash = hash_source_ip(&packet);

    // Verify hash is consistent
    assert_eq!(hash, hash_source_ip(&packet));
}

#[test]
fn test_hash_raw_ip_packet() {
    // Packet without Ethernet header (raw IP)
    let mut packet = vec![0u8; 20];
    packet[0] = 0x45; // IPv4 version 4, IHL 5

    // Source IP: 192.168.1.1
    packet[12] = 192;
    packet[13] = 168;
    packet[14] = 1;
    packet[15] = 1;

    let hash1 = hash_source_ip(&packet);
    let hash2 = hash_source_ip(&packet);

    assert_eq!(hash1, hash2);
}

#[test]
fn test_hash_consistency_same_source() {
    let mut packet1 = vec![0u8; 40];
    let mut packet2 = vec![0u8; 60]; // Different total length

    // Both packets from same source
    for packet in [&mut packet1, &mut packet2] {
        packet[12] = 0x08;
        packet[13] = 0x00;
        packet[14] = 0x45;
        packet[26..30].copy_from_slice(&[192, 168, 1, 1]);
    }

    let hash1 = hash_source_ip(&packet1);
    let hash2 = hash_source_ip(&packet2);

    // Same source IP should produce same hash regardless of packet length
    assert_eq!(hash1, hash2);
}

#[test]
fn test_hash_worker_distribution() {
    // Test that hashing distributes packets across workers
    let mut packets = Vec::new();

    for i in 0..10 {
        let mut packet = vec![0u8; 34];
        packet[12] = 0x08;
        packet[13] = 0x00;
        packet[14] = 0x45;

        // Different source IPs
        packet[26] = 192;
        packet[27] = 168;
        packet[28] = 1;
        packet[29] = i;

        packets.push(packet);
    }

    let num_workers = 4;
    let mut worker_counts = vec![0; num_workers];

    for packet in &packets {
        let hash = hash_source_ip(packet);
        let worker_id = hash % num_workers;
        worker_counts[worker_id] += 1;
    }

    // Verify all workers got at least one packet (with high probability)
    // This is probabilistic, but with 10 packets and 4 workers, it's very likely
    let used_workers = worker_counts.iter().filter(|&&count| count > 0).count();
    assert!(used_workers >= 2, "Expected at least 2 workers to be used, got {used_workers}");
}
