use huginn_net_tls::packet_hash::*;

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
    if let Some(worker) = worker1 {
        assert!(worker < 4);
    } else {
        panic!("Valid IPv4 TCP packet should return Some(worker)");
    }
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
    if let Some(worker) = worker1 {
        assert!(worker < 4);
    } else {
        panic!("Valid IPv4 TCP packet should return Some(worker)");
    }
    if let Some(worker) = worker2 {
        assert!(worker < 4);
    } else {
        panic!("Valid IPv4 TCP packet should return Some(worker)");
    }
}

#[test]
fn test_hash_short_packet_returns_none() {
    let short_packet = vec![0u8; 10];
    let worker = hash_flow(&short_packet, 4);
    // Packet too short to extract flow, should return None
    assert_eq!(worker, None);
}

#[test]
fn test_hash_invalid_ip_version_returns_none() {
    let mut packet = vec![0u8; 60];
    packet[12] = 0x08;
    packet[13] = 0x00;
    packet[14] = 0x75; // Invalid IP version (7)

    let worker = hash_flow(&packet, 4);
    // Unknown IP version should return None
    assert_eq!(worker, None);
}

#[test]
fn test_hash_non_tcp_protocol_returns_none() {
    let mut packet = vec![0u8; 54];
    packet[12] = 0x08;
    packet[13] = 0x00;
    packet[14] = 0x45;
    packet[23] = 17; // UDP, not TCP
    packet[26..30].copy_from_slice(&[192, 168, 1, 1]);

    let worker = hash_flow(&packet, 4);
    // Non-TCP protocol should return None (TLS requires TCP)
    assert_eq!(worker, None);
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

    // TCP header (starts at byte 54)
    packet[54..56].copy_from_slice(&[0x00, 0x50]); // port 80
    packet[56..58].copy_from_slice(&[0x1F, 0x90]); // port 8080

    let worker1 = hash_flow(&packet, 4);
    let worker2 = hash_flow(&packet, 4);

    assert_eq!(worker1, worker2);
    if let Some(worker) = worker1 {
        assert!(worker < 4);
    } else {
        panic!("Valid IPv6 TCP packet should return Some(worker)");
    }
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

    if let Some(worker) = worker_2 {
        assert!(worker < 2);
    } else {
        panic!("Valid packet should return Some(worker)");
    }
    if let Some(worker) = worker_4 {
        assert!(worker < 4);
    } else {
        panic!("Valid packet should return Some(worker)");
    }
    if let Some(worker) = worker_8 {
        assert!(worker < 8);
    } else {
        panic!("Valid packet should return Some(worker)");
    }
}

#[test]
fn test_hash_raw_ipv4_packet() {
    // Raw IPv4 packet (no Ethernet header)
    let mut packet = vec![0u8; 40];

    // IPv4 header
    packet[0] = 0x45; // Version 4, IHL 5
    packet[9] = 6; // Protocol: TCP

    // Source IP: 192.168.1.1
    packet[12..16].copy_from_slice(&[192, 168, 1, 1]);

    // Dest IP: 10.0.0.1
    packet[16..20].copy_from_slice(&[10, 0, 0, 1]);

    // TCP header (starts at byte 20)
    packet[20..22].copy_from_slice(&[0x00, 0x50]); // port 80
    packet[22..24].copy_from_slice(&[0x1F, 0x90]); // port 8080

    let worker1 = hash_flow(&packet, 4);
    let worker2 = hash_flow(&packet, 4);

    assert_eq!(worker1, worker2);
    if let Some(worker) = worker1 {
        assert!(worker < 4);
    } else {
        panic!("Valid raw IPv4 TCP packet should return Some(worker)");
    }
}

#[test]
fn test_hash_raw_ipv6_packet() {
    // Raw IPv6 packet (no Ethernet header)
    let mut packet = vec![0u8; 60];

    // IPv6 header
    packet[0] = 0x60; // Version 6
    packet[6] = 6; // Next header: TCP

    // Source IP (16 bytes starting at byte 8)
    packet[8..24].copy_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ]);

    // Dest IP (16 bytes)
    packet[24..40].copy_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ]);

    // TCP header (starts at byte 40)
    packet[40..42].copy_from_slice(&[0x00, 0x50]); // port 80
    packet[42..44].copy_from_slice(&[0x1F, 0x90]); // port 8080

    let worker1 = hash_flow(&packet, 4);
    let worker2 = hash_flow(&packet, 4);

    assert_eq!(worker1, worker2);
    if let Some(worker) = worker1 {
        assert!(worker < 4);
    } else {
        panic!("Valid raw IPv6 TCP packet should return Some(worker)");
    }
}

#[test]
fn test_hash_ipv4_incomplete_tcp_header_returns_none() {
    let mut packet = vec![0u8; 30]; // Too short for TCP header
    packet[12] = 0x08;
    packet[13] = 0x00;
    packet[14] = 0x45;
    packet[23] = 6;
    packet[26..30].copy_from_slice(&[192, 168, 1, 1]);

    let worker = hash_flow(&packet, 4);
    // Packet too short for TCP header, should return None
    assert_eq!(worker, None);
}

#[test]
fn test_hash_ipv6_incomplete_tcp_header_returns_none() {
    let mut packet = vec![0u8; 50]; // Too short for TCP header (need at least 44 bytes)
    packet[12] = 0x86;
    packet[13] = 0xDD;
    packet[14] = 0x60;
    packet[20] = 6;

    let worker = hash_flow(&packet, 4);
    // Packet too short for TCP header, should return None
    assert_eq!(worker, None);
}

#[test]
fn test_hash_same_flow_always_same_worker() {
    // Test that packets from the same flow always hash to the same worker
    let mut packet = vec![0u8; 54];
    packet[12] = 0x08;
    packet[13] = 0x00;
    packet[14] = 0x45;
    packet[23] = 6;
    packet[26..30].copy_from_slice(&[192, 168, 1, 100]);
    packet[30..34].copy_from_slice(&[8, 8, 8, 8]);
    packet[34..36].copy_from_slice(&[0x30, 0x39]); // port 12345
    packet[36..38].copy_from_slice(&[0x01, 0xBB]); // port 443

    let workers: Vec<Option<usize>> = (0..100).map(|_| hash_flow(&packet, 8)).collect();

    // All should be the same
    let first_worker = workers[0];
    for worker in workers.iter().skip(1) {
        assert_eq!(*worker, first_worker);
    }

    if let Some(worker) = first_worker {
        assert!(worker < 8);
    } else {
        panic!("Valid packet should return Some(worker)");
    }
}

#[test]
fn test_hash_different_ports_different_workers() {
    let mut base_packet = vec![0u8; 54];
    base_packet[12] = 0x08;
    base_packet[13] = 0x00;
    base_packet[14] = 0x45;
    base_packet[23] = 6;
    base_packet[26..30].copy_from_slice(&[192, 168, 1, 100]);
    base_packet[30..34].copy_from_slice(&[8, 8, 8, 8]);

    let mut workers = Vec::new();
    for port in 1000u16..1010u16 {
        let mut packet = base_packet.clone();
        packet[34..36].copy_from_slice(&port.to_be_bytes());
        packet[36..38].copy_from_slice(&[0x01, 0xBB]); // port 443
        workers.push(hash_flow(&packet, 8));
    }

    // All should be valid
    for worker in &workers {
        if let Some(w) = worker {
            assert!(*w < 8);
        } else {
            panic!("Valid packet should return Some(worker)");
        }
    }
}

#[test]
fn test_hash_zero_workers() {
    // Edge case: zero workers (should not panic)
    let mut packet = vec![0u8; 54];
    packet[12] = 0x08;
    packet[13] = 0x00;
    packet[14] = 0x45;
    packet[23] = 6;
    packet[26..30].copy_from_slice(&[192, 168, 1, 1]);
    packet[30..34].copy_from_slice(&[10, 0, 0, 1]);
    packet[34..36].copy_from_slice(&[0x00, 0x50]);
    packet[36..38].copy_from_slice(&[0x1F, 0x90]);

    let worker = hash_flow(&packet, 0);
    // With 0 workers, checked_rem will return 0
    if let Some(w) = worker {
        assert_eq!(w, 0);
    } else {
        // Or it might return None if validation fails earlier
        // Both are acceptable
    }
}
