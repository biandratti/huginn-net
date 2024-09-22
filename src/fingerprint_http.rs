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

fn handle_ipv4_packet(packet: Ipv4Packet) {
    let tcp_packet = TcpPacket::new(packet.payload()).unwrap();
    println!(
        "TCP Packet IPV4 from {}:{} to {}:{}",
        packet.get_source(),
        tcp_packet.get_source(),
        packet.get_destination(),
        tcp_packet.get_destination()
    );

    // Access TCP-specific fields
    println!("Sequence number: {}", tcp_packet.get_sequence());
    println!(
        "Acknowledgment number: {}",
        tcp_packet.get_acknowledgement()
    );
    println!("Flags: {:?}", tcp_packet.get_flags());
}

fn handle_ipv6_packet(packet: Ipv6Packet) {
    let tcp_packet = TcpPacket::new(packet.payload()).unwrap();
    println!(
        "TCP Packet IPV6 from {}:{} to {}:{}",
        packet.get_source(),
        tcp_packet.get_source(),
        packet.get_destination(),
        tcp_packet.get_destination()
    );

    // Access TCP-specific fields
    println!("Sequence number: {}", tcp_packet.get_sequence());
    println!(
        "Acknowledgment number: {}",
        tcp_packet.get_acknowledgement()
    );
    println!("Flags: {:?}", tcp_packet.get_flags());
}
