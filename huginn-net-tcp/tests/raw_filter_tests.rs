use std::net::IpAddr;

use huginn_net_tcp::filter::{FilterConfig, FilterMode, IpFilter, PortFilter};

/// Helper to create an IPv4 TCP packet (minimal: IP header + TCP ports)
fn create_ipv4_tcp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    let mut packet = vec![0u8; 40];
    packet[0] = 0x45; // IPv4, IHL=5
    packet[9] = 6; // TCP protocol
    packet[12..16].copy_from_slice(&src_ip);
    packet[16..20].copy_from_slice(&dst_ip);
    packet[20..22].copy_from_slice(&src_port.to_be_bytes());
    packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
    packet
}

/// Helper to create an Ethernet frame with IPv4 TCP packet
fn create_ethernet_ipv4_tcp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    let mut packet = vec![0u8; 54];
    packet[12..14].copy_from_slice(&[0x08, 0x00]); // IPv4 EtherType
    packet[14] = 0x45; // IPv4, IHL=5
    packet[23] = 6; // TCP protocol
    packet[26..30].copy_from_slice(&src_ip);
    packet[30..34].copy_from_slice(&dst_ip);
    packet[34..36].copy_from_slice(&src_port.to_be_bytes());
    packet[36..38].copy_from_slice(&dst_port.to_be_bytes());
    packet
}

#[test]
fn test_raw_filter_ipv4_raw_packet() {
    let packet = create_ipv4_tcp_packet([192, 168, 1, 100], [8, 8, 8, 8], 12345, 443);

    assert_eq!(packet.len(), 40);
    assert_eq!(packet[0], 0x45); // IPv4, IHL=5
    assert_eq!(packet[9], 6); // TCP protocol
}

#[test]
fn test_raw_filter_ethernet_frame() {
    let packet = create_ethernet_ipv4_tcp_packet([192, 168, 1, 100], [8, 8, 8, 8], 12345, 443);

    assert_eq!(packet.len(), 54);
    assert_eq!(&packet[12..14], &[0x08, 0x00]); // IPv4 EtherType
    assert_eq!(packet[14], 0x45); // IPv4, IHL=5
    assert_eq!(packet[23], 6); // TCP protocol
}

#[test]
fn test_raw_filter_allows_matching_destination_port() {
    let filter = FilterConfig::new()
        .mode(FilterMode::Allow)
        .with_port_filter(PortFilter::new().destination(443));

    let src_ip: IpAddr = "192.168.1.100"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IP: {e}"));
    let dst_ip: IpAddr = "8.8.8.8"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IP: {e}"));

    assert!(filter.should_process(&src_ip, &dst_ip, 12345, 443));
}

#[test]
fn test_raw_filter_blocks_non_matching_destination_port() {
    let filter = FilterConfig::new()
        .mode(FilterMode::Allow)
        .with_port_filter(PortFilter::new().destination(443));

    let src_ip: IpAddr = "192.168.1.100"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IP: {e}"));
    let dst_ip: IpAddr = "8.8.8.8"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IP: {e}"));

    assert!(!filter.should_process(&src_ip, &dst_ip, 12345, 80));
}

#[test]
fn test_raw_filter_allows_matching_source_ip() {
    let filter = FilterConfig::new().mode(FilterMode::Allow).with_ip_filter(
        IpFilter::new()
            .allow("192.168.1.100")
            .unwrap_or_else(|e| panic!("Invalid IP: {e}"))
            .source_only(),
    );

    let src_ip: IpAddr = "192.168.1.100"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IP: {e}"));
    let dst_ip: IpAddr = "8.8.8.8"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IP: {e}"));

    assert!(filter.should_process(&src_ip, &dst_ip, 12345, 443));
}

#[test]
fn test_raw_filter_blocks_non_matching_source_ip() {
    let filter = FilterConfig::new().mode(FilterMode::Allow).with_ip_filter(
        IpFilter::new()
            .allow("192.168.1.100")
            .unwrap_or_else(|e| panic!("Invalid IP: {e}"))
            .source_only(),
    );

    let src_ip: IpAddr = "10.0.0.1"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IP: {e}"));
    let dst_ip: IpAddr = "8.8.8.8"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IP: {e}"));

    assert!(!filter.should_process(&src_ip, &dst_ip, 12345, 443));
}

#[test]
fn test_raw_filter_combined_filters() {
    let filter = FilterConfig::new()
        .mode(FilterMode::Allow)
        .with_port_filter(PortFilter::new().destination(443))
        .with_ip_filter(
            IpFilter::new()
                .allow("192.168.1.100")
                .unwrap_or_else(|e| panic!("Invalid IP: {e}"))
                .source_only(),
        );

    let src_ip: IpAddr = "192.168.1.100"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IP: {e}"));
    let dst_ip: IpAddr = "8.8.8.8"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IP: {e}"));

    assert!(filter.should_process(&src_ip, &dst_ip, 12345, 443));

    assert!(!filter.should_process(&src_ip, &dst_ip, 12345, 80));

    let wrong_src: IpAddr = "10.0.0.1"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IP: {e}"));
    assert!(!filter.should_process(&wrong_src, &dst_ip, 12345, 443));
}

#[test]
fn test_raw_filter_deny_mode() {
    let filter = FilterConfig::new()
        .mode(FilterMode::Deny)
        .with_port_filter(PortFilter::new().destination(22));

    let src_ip: IpAddr = "192.168.1.100"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IP: {e}"));
    let dst_ip: IpAddr = "8.8.8.8"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IP: {e}"));

    assert!(!filter.should_process(&src_ip, &dst_ip, 12345, 22));
    assert!(filter.should_process(&src_ip, &dst_ip, 12345, 443));
}

#[test]
fn test_raw_filter_no_filter_allows_all() {
    let filter = FilterConfig::new();

    let src_ip: IpAddr = "192.168.1.100"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IP: {e}"));
    let dst_ip: IpAddr = "8.8.8.8"
        .parse()
        .unwrap_or_else(|e| panic!("Invalid IP: {e}"));

    assert!(filter.should_process(&src_ip, &dst_ip, 12345, 443));
    assert!(filter.should_process(&src_ip, &dst_ip, 54321, 80));
}
