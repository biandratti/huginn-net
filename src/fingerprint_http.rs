use crate::tcp_package::TcpPackage;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::{ipv6::Ipv6Packet, tcp::TcpPacket, Packet};

pub fn handle_ethernet_packet(packet: EthernetPacket) {
    match packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4_packet = Ipv4Packet::new(packet.payload()).unwrap();
            if ipv4_packet.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Tcp
            {
                handle_ipv4_packet(ipv4_packet);
            }
        }
        EtherTypes::Ipv6 => {
            let ipv6_packet = Ipv6Packet::new(packet.payload()).unwrap();
            if ipv6_packet.get_next_header() == pnet::packet::ip::IpNextHeaderProtocols::Tcp {
                handle_ipv6_packet(ipv6_packet);
            }
        }
        _ => {}
    }
}

pub fn handle_ipv4_packet(packet: Ipv4Packet) {
    let tcp_packet = TcpPacket::new(packet.payload()).unwrap();

    // Calculate network distance (hops) from TTL
    let ttl = packet.get_ttl();
    let hops = 64 - ttl; // Adjust based on common defaults (e.g., 64 for Linux, 128 for Windows)

    // Extract TCP options (for now, hardcoded as a simple example)
    let options = "mss*20,7:mss,sok,ts,nop,ws".to_string();

    // Guess OS based on the window size as a simple fingerprinting technique
    let os_guess = if tcp_packet.get_window() == 5840 {
        Some("Linux 3.11 and newer".to_string())
    } else if tcp_packet.get_window() == 8192 {
        Some("Windows XP".to_string())
    } else {
        Some("Unknown OS".to_string())
    };

    let raw_sig = format!("4:{}+{}:0:1460:{}", ttl, hops, options);

    // Create a TcpPackage instance
    let tcp_package = TcpPackage {
        client: format!("{}/{}", packet.get_source(), tcp_packet.get_source()),
        os: os_guess,
        dist: hops.into(),
        params: String::from("none"), // Placeholder, real extraction needed for TCP options
        raw_sig,
    };

    println!("{}", tcp_package);
}

fn handle_ipv6_packet(packet: Ipv6Packet) {
    let tcp_packet = TcpPacket::new(packet.payload()).unwrap();

    let tcp_package = TcpPackage {
        client: format!("{}/{}", packet.get_source(), tcp_packet.get_source()),
        os: None,
        dist: -1,
        params: String::from("none"),
        raw_sig: String::from("Not available"),
    };

    println!("{}", tcp_package);
}
