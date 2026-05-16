use huginn_net::packet_parser::{detect_datalink_format, parse_packet, DatalinkFormat, IpPacket};

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
    // Raw IPv4 packet (no datalink header)
    let raw_ipv4 = vec![
        0x45, 0x00, 0x00, 0x1c, // Version=4, IHL=5, TOS=0, Total Length=28
        0x00, 0x00, 0x40, 0x00, // ID=0, Flags=0x4000 (DF), Fragment Offset=0
        0x40, 0x06, 0x7c, 0xb0, // TTL=64, Protocol=TCP(6), Checksum
        0xc0, 0xa8, 0x01, 0x01, // Source IP: 192.168.1.1
        0xc0, 0xa8, 0x01, 0x02, // Dest IP: 192.168.1.2
    ];
    let format = detect_datalink_format(&raw_ipv4);
    assert_eq!(format, Some(DatalinkFormat::RawIp));
}

#[test]
fn test_detect_raw_ipv6() {
    // Raw IPv6 packet (no datalink header)
    let raw_ipv6 = vec![
        0x60, 0x00, 0x00, 0x00, // Version=6, Traffic Class=0, Flow Label=0
        0x00, 0x00, 0x06, 0x40, // Payload Length=0, Next Header=TCP(6), Hop Limit=64
        // Source address: 2001:db8::1
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, // Destination address: 2001:db8::2
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ];
    let format = detect_datalink_format(&raw_ipv6);
    assert_eq!(format, Some(DatalinkFormat::RawIp));
}

#[test]
fn test_detect_ethernet_ipv4() {
    // Ethernet frame with IPv4 payload
    let ethernet_ipv4 = vec![
        // Ethernet header (14 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Destination MAC
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source MAC
        0x08, 0x00, // EtherType: IPv4
        // IPv4 header
        0x45, 0x00, 0x00, 0x1c, // Version=4, IHL=5, TOS=0, Total Length=28
        0x00, 0x00, 0x40, 0x00, // ID=0, Flags=0x4000 (DF), Fragment Offset=0
        0x40, 0x06, 0x7c, 0xb0, // TTL=64, Protocol=TCP(6), Checksum
        0xc0, 0xa8, 0x01, 0x01, // Source IP: 192.168.1.1
        0xc0, 0xa8, 0x01, 0x02, // Dest IP: 192.168.1.2
    ];
    let format = detect_datalink_format(&ethernet_ipv4);
    assert_eq!(format, Some(DatalinkFormat::Ethernet));
}

#[test]
fn test_detect_ethernet_ipv6() {
    // Ethernet frame with IPv6 payload
    let ethernet_ipv6 = vec![
        // Ethernet header (14 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Destination MAC
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source MAC
        0x86, 0xDD, // EtherType: IPv6
        // IPv6 header (40 bytes)
        0x60, 0x00, 0x00, 0x00, // Version=6, Traffic Class=0, Flow Label=0
        0x00, 0x00, 0x06, 0x40, // Payload Length=0, Next Header=TCP(6), Hop Limit=64
        // Source address: 2001:db8::1
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, // Destination address: 2001:db8::2
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ];
    let format = detect_datalink_format(&ethernet_ipv6);
    assert_eq!(format, Some(DatalinkFormat::Ethernet));
}

#[test]
fn test_parse_ethernet_ipv4() {
    // Test parsing Ethernet frame with IPv4
    let ethernet_ipv4 = vec![
        // Ethernet header (14 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Destination MAC
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source MAC
        0x08, 0x00, // EtherType: IPv4
        // IPv4 header
        0x45, 0x00, 0x00, 0x1c, // Version=4, IHL=5, TOS=0, Total Length=28
        0x00, 0x00, 0x40, 0x00, // ID=0, Flags=0x4000 (DF), Fragment Offset=0
        0x40, 0x06, 0x7c, 0xb0, // TTL=64, Protocol=TCP(6), Checksum
        0xc0, 0xa8, 0x01, 0x01, // Source IP: 192.168.1.1
        0xc0, 0xa8, 0x01, 0x02, // Dest IP: 192.168.1.2
    ];
    match parse_packet(&ethernet_ipv4) {
        IpPacket::Ipv4(ip_data) => {
            assert_eq!(ip_data[0], 0x45); // Version=4, IHL=5
            assert_eq!(ip_data.len(), 20); // IPv4 header length
        }
        _ => panic!("Expected IPv4 packet"),
    }
}

#[test]
fn test_parse_raw_ipv6() {
    // Test parsing raw IPv6 packet
    let raw_ipv6 = vec![
        0x60, 0x00, 0x00, 0x00, // Version=6, Traffic Class=0, Flow Label=0
        0x00, 0x00, 0x06, 0x40, // Payload Length=0, Next Header=TCP(6), Hop Limit=64
        // Source address: 2001:db8::1
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, // Destination address: 2001:db8::2
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ];
    match parse_packet(&raw_ipv6) {
        IpPacket::Ipv6(ip_data) => {
            assert_eq!(ip_data[0], 0x60); // Version=6
            assert_eq!(ip_data.len(), 40); // IPv6 header length
        }
        _ => panic!("Expected IPv6 packet"),
    }
}

#[test]
fn test_parse_null_datalink_ipv6() {
    // Test parsing NULL datalink with IPv6
    let null_ipv6 = vec![
        0x1e, 0x00, 0x00, 0x00, // NULL header
        0x60, 0x00, 0x00, 0x00, // IPv6 header start (version=6)
        0x00, 0x14, 0x06, 0x40, // IPv6 payload length, next header (TCP), hop limit
        // Add minimal IPv6 addresses (32 bytes total)
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, // src
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, // dst
    ];
    match parse_packet(&null_ipv6) {
        IpPacket::Ipv6(ip_data) => {
            assert_eq!(ip_data[0], 0x60); // Version=6
            assert_eq!(ip_data.len(), 40); // IPv6 header (40 bytes total)
        }
        _ => panic!("Expected NULL datalink IPv6 packet"),
    }
}
