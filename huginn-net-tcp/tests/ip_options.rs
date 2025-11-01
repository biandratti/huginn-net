use huginn_net_tcp::ip_options::IpOptions;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;

#[test]
fn test_ipv4_options_length() {
    let mut data = vec![0u8; 24];
    data[0] = 0x46; // Version 4, IHL 6
    let packet_opt = Ipv4Packet::new(&data);
    assert!(packet_opt.is_some(), "Failed to create IPv4 packet");
    let packet = match packet_opt {
        Some(pkt) => pkt,
        None => panic!("Should not fail after assert"),
    };

    assert_eq!(IpOptions::calculate_ipv4_length(&packet), 4);
}

#[test]
fn test_ipv6_direct_tcp() {
    let mut data = vec![0u8; 40];
    data[0] = 0x60; // Version 6
    data[6] = IpNextHeaderProtocols::Tcp.0; // Next Header = TCP

    let packet_opt = Ipv6Packet::new(&data);
    assert!(packet_opt.is_some(), "Failed to create IPv6 packet");
    let packet = match packet_opt {
        Some(pkt) => pkt,
        None => panic!("Should not fail after assert"),
    };
    assert_eq!(IpOptions::calculate_ipv6_length(&packet), 0);
}

#[test]
fn test_ipv6_fragment() {
    let mut data = vec![0u8; 48];
    data[0] = 0x60; // Version 6
    data[6] = IpNextHeaderProtocols::Ipv6Frag.0; // Next Header = Fragment
    data[4] = 0; // Length high byte
    data[5] = 8; // Length low byte
    data[40] = IpNextHeaderProtocols::Tcp.0; // Next Header = TCP

    let packet_opt = Ipv6Packet::new(&data);
    assert!(packet_opt.is_some(), "Failed to create IPv6 fragment packet");
    let packet = match packet_opt {
        Some(pkt) => pkt,
        None => panic!("Should not fail after assert"),
    };
    assert_eq!(IpOptions::calculate_ipv6_length(&packet), 8);
}
