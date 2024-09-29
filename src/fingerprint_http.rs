use crate::tcp_package::TcpPackage;
use crate::tcp_signature::TcpSignature;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpOption, TcpOptionNumbers};
use pnet::packet::{ipv6::Ipv6Packet, tcp::TcpPacket, Packet};

pub fn handle_ethernet_packet(packet: EthernetPacket, signatures: &Vec<TcpSignature>) {
    match packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4_packet: Ipv4Packet = Ipv4Packet::new(packet.payload()).unwrap();
            if ipv4_packet.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Tcp
            {
                handle_ipv4_packet(ipv4_packet, signatures);
            }
        }
        EtherTypes::Ipv6 => {
            let ipv6_packet = Ipv6Packet::new(packet.payload()).unwrap();
            if ipv6_packet.get_next_header() == pnet::packet::ip::IpNextHeaderProtocols::Tcp {
                // panic!("ipv6 not supported");
            }
        }
        _ => {}
    }
}

// Matching packet to fingerprint based on TCP signatures
fn match_packet_to_fingerprint<'a>(
    ipv4_packet: &Ipv4Packet,
    tcp_packet: &TcpPacket,
    signatures: &'a Vec<TcpSignature>,
) -> Option<&'a TcpSignature> {
    let packet_ttl: u8 = ipv4_packet.get_ttl();
    let packet_window_size: u16 = tcp_packet.get_window();

    let packet_mss: Option<u16> = extract_mss(tcp_packet);
    let packet_options: Vec<TcpOption> = tcp_packet.get_options();

    println!(
        "Packet: TTL: {} - Window: {} - MSS: {:?} - Options: {:?}",
        packet_ttl, packet_window_size, packet_mss, packet_options
    );

    // Define a threshold for a good match (you can adjust this)
    let threshold = 0.0;

    let mut best_match: Option<&TcpSignature> = None;
    let mut best_score: f64 = 0.2;

    // Iterate through the signatures and calculate a matching score
    for signature in signatures {
        let mut score = 0.0;
        let mut max_score = 0.0;

        // TTL match (high importance)
        max_score += 1.0;
        if packet_ttl == signature.ittl {
            score += 1.0;
        }

        // Window size match (moderate importance)
        max_score += 1.0;
        if packet_window_size == signature.window {
            score += 1.0;
        }

        // MSS match (moderate importance)
        max_score += 1.0;
        match packet_mss {
            Some(mss) if mss == signature.mss => {
                score += 1.0;
            }
            _ => {}
        }

        // TCP options match (lower importance but still relevant)
        max_score += 1.0;
        /*        if compare_options(&packet_options, &signature.options) {
            score += 1.0;
        }*/

        // Calculate the normalized score
        let match_score = score / max_score;

        // If the match score is higher than the threshold, consider it a match
        if match_score >= threshold && match_score > best_score {
            best_score = match_score;
            best_match = Some(signature);
        }
    }

    // println!("best_match: {:?}", best_match);
    best_match
}

fn extract_mss(tcp_packet: &TcpPacket) -> Option<u16> {
    for option in tcp_packet.get_options() {
        match option.number {
            TcpOptionNumbers::MSS => {
                if option.data.len() == 2 {
                    let mss_value: u16 = ((option.data[0] as u16) << 8) | (option.data[1] as u16);
                    return Some(mss_value);
                }
            }
            _ => continue,
        }
    }
    None
}

// Function to handle IPv4 packets
pub fn handle_ipv4_packet(packet: Ipv4Packet, signatures: &Vec<TcpSignature>) {
    let tcp_packet: TcpPacket = TcpPacket::new(packet.payload()).unwrap();

    let tcp_signature: Option<&TcpSignature> =
        match_packet_to_fingerprint(&packet, &tcp_packet, signatures);

    let tcp_package = TcpPackage {
        client: format!("{}/{}", packet.get_source(), tcp_packet.get_source()),
        os: tcp_signature.map(|sig| sig.os.clone()),
        dist: 64i64 - packet.get_ttl() as i64,
        params: String::from("none"),
        raw_sig: tcp_signature
            .map(|sig| sig.sig.clone())
            .unwrap_or_else(|| "Unknown sig".to_string()),
    };

    println!("{}", tcp_package);
}
