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

    // Calculate network distance (hops) from TTL
    let ttl = packet.get_ttl();
    let hops = 64 - ttl; // Adjust based on common defaults (e.g., 64 for Linux, 128 for Windows)

    // Extract TCP options (mss, ws, etc.)
    let window_size = tcp_packet.get_window();
    let options = format!("mss*20,7:mss,sok,ts,nop,ws");

    // Guess OS based on fingerprint (window size as a simple example)
    let os_guess = if window_size == 5840 {
        "Linux 3.11 and newer"
    } else if window_size == 8192 {
        "Windows XP"
    } else {
        "Unknown OS"
    };

    // Generate raw signature (simplified example)
    let raw_sig = format!("4:{}+{}:0:1460:{}", ttl, hops, options);

    // Output in p0f format
    println!(
        ".-[ {}/{} -> {}/{} (syn) ]-\n\
        |\n\
        | client   = {}/{}\n\
        | os       = {}\n\
        | dist     = {}\n\
        | params   = none\n\
        | raw_sig  = {}\n",
        packet.get_source(),
        tcp_packet.get_source(),
        packet.get_destination(),
        tcp_packet.get_destination(),
        packet.get_source(),
        tcp_packet.get_source(),
        os_guess,
        hops,
        raw_sig
    );
}

fn handle_ipv6_packet(packet: Ipv6Packet) {
    let tcp_packet = TcpPacket::new(packet.payload()).unwrap();

    // IPv6 version, print similar output
    println!(
        ".-[ {}/{} -> {}/{} (syn) ]-\n\
        |\n\
        | client   = {}/{}\n\
        | os       = OS Detection not implemented for IPv6\n\
        | dist     = Not available\n\
        | params   = none\n\
        | raw_sig  = Not available\n",
        packet.get_source(),
        tcp_packet.get_source(),
        packet.get_destination(),
        tcp_packet.get_destination(),
        packet.get_source(),
        tcp_packet.get_source()
    );
}
