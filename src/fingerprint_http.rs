use crate::tcp_fingerprint::{TcpFingerprint, TcpOption};
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
                //panic!("ipv6 not supported");
            }
        }
        _ => {}
    }
}

fn match_packet_to_fingerprint(packet: &Ipv4Packet, tcp_packet: &TcpPacket) -> Option<String> {
    let ttl = packet.get_ttl();
    let window_size = tcp_packet.get_window();
    let mss = extract_mss_option(tcp_packet);
    let options = extract_tcp_options(tcp_packet);

    let signatures = vec![
        TcpFingerprint::linux_3_11_and_newer(),
        TcpFingerprint::windows_xp(),
    ];

    for sig in signatures {
        if sig.ittl == ttl
            && sig.window == window_size.into()
            && sig.mss == mss
            && sig.options == options
        {
            return Some(format!("Matched OS: {:?}", sig));
        }
    }

    None
}

fn extract_mss_option(_tcp_packet: &TcpPacket) -> u16 {
    1460
}

fn extract_tcp_options(_tcp_packet: &TcpPacket) -> Vec<TcpOption> {
    vec![TcpOption::Mss(1460), TcpOption::Nop]
}

pub fn handle_ipv4_packet(packet: Ipv4Packet) {
    let tcp_packet = TcpPacket::new(packet.payload()).unwrap();

    let os_guess = match_packet_to_fingerprint(&packet, &tcp_packet)
        .unwrap_or_else(|| "Unknown OS".to_string());

    let tcp_package = TcpPackage {
        client: format!("{}/{}", packet.get_source(), tcp_packet.get_source()),
        os: Some(os_guess),
        dist: 64i64 - packet.get_ttl() as i64,
        params: String::from("none"),
        raw_sig: format!("4:{}:{}:1460", packet.get_ttl(), tcp_packet.get_window()),
    };

    println!("{}", tcp_package);
}
