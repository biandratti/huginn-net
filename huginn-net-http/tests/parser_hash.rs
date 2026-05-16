use huginn_net_http::packet_hash::*;

#[test]
fn test_hash_ipv4_tcp_flow() {
    // Ethernet + IPv4 + TCP packet
    let mut packet = vec![0u8; 54];

    // Ethernet header
    packet[12] = 0x08; // IPv4 EtherType
    packet[13] = 0x00;

    // IPv4 header (starts at byte 14)
    packet[14] = 0x45; // Version 4, IHL 5 (20 bytes)
    packet[23] = 6; // Protocol: TCP

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

    // TCP header (starts at byte 34)
    packet[34] = 0x00; // Source port: 80
    packet[35] = 0x50;
    packet[36] = 0x1F; // Dest port: 8080
    packet[37] = 0x90;

    let worker1 = hash_flow(&packet, 4);
    let worker2 = hash_flow(&packet, 4);

    // Same packet should always go to same worker
    assert_eq!(worker1, worker2);
    assert!(worker1 < 4);
}

#[test]
fn test_hash_ipv4_different_flows() {
    let mut packet1 = vec![0u8; 54];
    let mut packet2 = vec![0u8; 54];

    // Setup both as valid IPv4 TCP packets
    for packet in [&mut packet1, &mut packet2] {
        packet[12] = 0x08;
        packet[13] = 0x00;
        packet[14] = 0x45;
        packet[23] = 6;
    }

    // Packet 1: 192.168.1.1:80 -> 10.0.0.1:8080
    packet1[26..30].copy_from_slice(&[192, 168, 1, 1]);
    packet1[30..34].copy_from_slice(&[10, 0, 0, 1]);
    packet1[34..36].copy_from_slice(&[0x00, 0x50]); // port 80
    packet1[36..38].copy_from_slice(&[0x1F, 0x90]); // port 8080

    // Packet 2: 192.168.1.2:80 -> 10.0.0.1:8080 (different source IP)
    packet2[26..30].copy_from_slice(&[192, 168, 1, 2]);
    packet2[30..34].copy_from_slice(&[10, 0, 0, 1]);
    packet2[34..36].copy_from_slice(&[0x00, 0x50]);
    packet2[36..38].copy_from_slice(&[0x1F, 0x90]);

    let worker1 = hash_flow(&packet1, 4);
    let worker2 = hash_flow(&packet2, 4);

    // Different flows should likely go to different workers
    // (not guaranteed, but very likely with good hash function)
    assert!(worker1 < 4);
    assert!(worker2 < 4);
}

#[test]
fn test_hash_fallback_on_short_packet() {
    let short_packet = vec![0u8; 10];
    let worker = hash_flow(&short_packet, 4);
    assert!(worker < 4);
}

#[test]
fn test_hash_fallback_on_invalid_ip_version() {
    let mut packet = vec![0u8; 60];
    packet[12] = 0x08;
    packet[13] = 0x00;
    packet[14] = 0x75; // Invalid IP version (7)

    let worker = hash_flow(&packet, 4);
    assert!(worker < 4);
}

#[test]
fn test_hash_non_tcp_protocol() {
    let mut packet = vec![0u8; 54];
    packet[12] = 0x08;
    packet[13] = 0x00;
    packet[14] = 0x45;
    packet[23] = 17; // UDP, not TCP
    packet[26..30].copy_from_slice(&[192, 168, 1, 1]);

    let worker = hash_flow(&packet, 4);
    assert!(worker < 4);
}

#[test]
fn test_hash_ipv6_tcp_flow() {
    let mut packet = vec![0u8; 74];

    // Ethernet header
    packet[12] = 0x86; // IPv6 EtherType
    packet[13] = 0xDD;

    // IPv6 header (starts at byte 14)
    packet[14] = 0x60; // Version 6
    packet[20] = 6; // Next header: TCP

    // Source IP (16 bytes)
    packet[22..38].copy_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ]);

    // Dest IP (16 bytes)
    packet[38..54].copy_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ]);

    // TCP header
    packet[54..56].copy_from_slice(&[0x00, 0x50]); // port 80
    packet[56..58].copy_from_slice(&[0x1F, 0x90]); // port 8080

    let worker1 = hash_flow(&packet, 4);
    let worker2 = hash_flow(&packet, 4);

    assert_eq!(worker1, worker2);
    assert!(worker1 < 4);
}

#[test]
fn test_hash_consistency_across_workers() {
    let mut packet = vec![0u8; 54];
    packet[12] = 0x08;
    packet[13] = 0x00;
    packet[14] = 0x45;
    packet[23] = 6;
    packet[26..30].copy_from_slice(&[192, 168, 1, 1]);
    packet[30..34].copy_from_slice(&[10, 0, 0, 1]);
    packet[34..36].copy_from_slice(&[0x00, 0x50]);
    packet[36..38].copy_from_slice(&[0x1F, 0x90]);

    // Same packet should map consistently regardless of worker count
    let worker_2 = hash_flow(&packet, 2);
    let worker_4 = hash_flow(&packet, 4);
    let worker_8 = hash_flow(&packet, 8);

    assert!(worker_2 < 2);
    assert!(worker_4 < 4);
    assert!(worker_8 < 8);
}
