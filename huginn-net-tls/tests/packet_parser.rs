use huginn_net_tls::packet_parser::{
    detect_datalink_format, parse_packet, DatalinkFormat, IpPacket,
};

#[test]
fn test_detect_null_datalink() {
    // NULL datalink: 4-byte header + IPv6 packet
    let null_packet = vec![
        0x1e, 0x00, 0x00, 0x00, // NULL header
        0x60, 0x00, 0x00, 0x00, // IPv6 header start (version=6)
        0x00, 0x14, 0x06, 0x40, // IPv6 payload length, next header (TCP), hop limit
        // Add minimal IPv6 addresses (32 bytes total)
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, // src
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, // dst
    ];

    let format = detect_datalink_format(&null_packet);
    assert_eq!(format, Some(DatalinkFormat::Null));
}

#[test]
fn test_detect_raw_ipv4() {
    // Raw IPv4 packet (no Ethernet header)
    let raw_ipv4 = vec![
        0x45, 0x00, 0x00, 0x1c, // Version=4, IHL=5, TOS=0, Total Length=28
        0x00, 0x01, 0x40, 0x00, // ID=1, Flags=0x4000 (DF), Fragment Offset=0
        0x40, 0x06, 0x00, 0x00, // TTL=64, Protocol=6 (TCP), Header Checksum=0
        0xc0, 0xa8, 0x01, 0x01, // Source IP: 192.168.1.1
        0xc0, 0xa8, 0x01, 0x02, // Dest IP: 192.168.1.2
    ];

    let format = detect_datalink_format(&raw_ipv4);
    assert_eq!(format, Some(DatalinkFormat::RawIp));
}

#[test]
fn test_detect_raw_ipv6() {
    // Raw IPv6 packet (no Ethernet header)
    let raw_ipv6 = vec![
        0x60, 0x00, 0x00, 0x00, // Version=6, Traffic Class=0, Flow Label=0
        0x00, 0x14, 0x06, 0x40, // Payload Length=20, Next Header=6 (TCP), Hop Limit=64
        // IPv6 addresses (32 bytes)
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, // src
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, // dst
    ];

    let format = detect_datalink_format(&raw_ipv6);
    assert_eq!(format, Some(DatalinkFormat::RawIp));
}

#[test]
fn test_detect_ethernet_ipv4() {
    // Ethernet frame with IPv4
    let ethernet_ipv4 = vec![
        // Ethernet header (14 bytes)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Destination MAC
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // Source MAC
        0x08, 0x00, // EtherType: IPv4
        // IPv4 packet
        0x45, 0x00, 0x00, 0x1c, // Version=4, IHL=5, TOS=0, Total Length=28
        0x00, 0x01, 0x40, 0x00, // ID=1, Flags=0x4000 (DF), Fragment Offset=0
        0x40, 0x06, 0x00, 0x00, // TTL=64, Protocol=6 (TCP), Header Checksum=0
        0xc0, 0xa8, 0x01, 0x01, // Source IP: 192.168.1.1
        0xc0, 0xa8, 0x01, 0x02, // Dest IP: 192.168.1.2
    ];

    let format = detect_datalink_format(&ethernet_ipv4);
    assert_eq!(format, Some(DatalinkFormat::Ethernet));
}

#[test]
fn test_parse_null_datalink_packet() {
    // NULL datalink packet with IPv6
    let null_packet = vec![
        0x1e, 0x00, 0x00, 0x00, // NULL header
        0x60, 0x00, 0x00, 0x00, // IPv6 header start
        0x00, 0x14, 0x06, 0x40, // IPv6 payload length, next header, hop limit
        // IPv6 addresses (32 bytes)
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02,
    ];

    let result = parse_packet(&null_packet);
    match result {
        IpPacket::Ipv6(ip_data) => {
            // Should point to IPv6 data (after NULL header)
            assert_eq!(ip_data[0] & 0xF0, 0x60); // IPv6 version
        }
        _ => panic!("Expected IPv6 packet"),
    }
}

#[test]
fn test_parse_raw_ipv4_packet() {
    let raw_ipv4 = vec![
        0x45, 0x00, 0x00, 0x1c, // IPv4 header
        0x00, 0x01, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, // Source IP
        0xc0, 0xa8, 0x01, 0x02, // Dest IP
    ];

    let result = parse_packet(&raw_ipv4);
    match result {
        IpPacket::Ipv4(ip_data) => {
            assert_eq!(ip_data[0] & 0xF0, 0x40); // IPv4 version
        }
        _ => panic!("Expected IPv4 packet"),
    }
}

#[test]
fn test_parse_ethernet_packet() {
    let ethernet_ipv4 = vec![
        // Ethernet header
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Dest MAC
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // Src MAC
        0x08, 0x00, // EtherType: IPv4
        // IPv4 packet
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01,
        0x01, 0xc0, 0xa8, 0x01, 0x02,
    ];

    let result = parse_packet(&ethernet_ipv4);
    match result {
        IpPacket::Ipv4(ip_data) => {
            // Should point to IPv4 data (after Ethernet header)
            assert_eq!(ip_data[0] & 0xF0, 0x40); // IPv4 version
        }
        _ => panic!("Expected IPv4 packet"),
    }
}

#[test]
fn test_parse_invalid_packet() {
    let invalid_packet = vec![0x00, 0x01, 0x02]; // Too small

    let result = parse_packet(&invalid_packet);
    match result {
        IpPacket::None => {} // Expected
        _ => panic!("Expected None for invalid packet"),
    }
}

#[test]
fn test_parse_unknown_ethernet_type() {
    let unknown_ethernet = vec![
        // Ethernet header with unknown EtherType
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Dest MAC
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // Src MAC
        0xFF, 0xFF, // Unknown EtherType
        0x45, 0x00, 0x00, 0x1c, // Would be IPv4 but wrong EtherType
    ];

    let result = parse_packet(&unknown_ethernet);
    match result {
        IpPacket::None => {} // Expected - unknown EtherType
        _ => panic!("Expected None for unknown EtherType"),
    }
}
