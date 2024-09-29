use crate::tcp_package::TcpPackage;
use crate::tcp_signature::TcpSignature;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpOption;
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

    // Extract MSS and TCP Options from TcpPacket
    let packet_mss: u16 = extract_mss_option(tcp_packet).unwrap_or(0);
    let packet_options: Vec<TcpOption> = tcp_packet.get_options();

    /*println!(
        "Packet: TTL: {} - Window: {} - MSS: {} - Options: {:?}",
        packet_ttl, packet_window_size, packet_mss, packet_options
    );*/

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
        if packet_mss == signature.mss {
            score += 1.0;
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

// Extract the MSS option from the TCP packet
fn extract_mss_option(tcp_packet: &TcpPacket) -> Option<u16> {
    let options = tcp_packet.get_options_raw(); // Get the raw options bytes
    let mut i = 0;

    // Iterate through the options bytes
    while i < options.len() {
        let kind = options[i]; // First byte is the option kind
        match kind {
            0 => break,  // End of options list
            1 => i += 1, // No-op option (1 byte)
            2 => {
                // MSS option has kind 2 and a length of 4
                if options.len() >= i + 4 {
                    let mss = u16::from_be_bytes([options[i + 2], options[i + 3]]);
                    return Some(mss);
                }
                break;
            }
            _ => {
                // Other options; skip over them using the length field
                if i + 1 < options.len() {
                    let length = options[i + 1] as usize;
                    if length < 2 {
                        break;
                    }
                    i += length;
                } else {
                    break;
                }
            }
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
