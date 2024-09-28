use crate::tcp_package::TcpPackage;
use crate::tcp_signature::TcpSignature;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
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
    // Extract TTL from Ipv4Packet
    let packet_ttl: u8 = ipv4_packet.get_ttl();

    // Extract window size from TcpPacket
    let packet_window_size: u16 = tcp_packet.get_window();

    // Extract MSS and TCP Options from TcpPacket
    let packet_mss: u16 = extract_mss_option(&tcp_packet).unwrap_or(1460);

    println!(
        "Packet: TTL: {} - Window: {} - MSS: {}",
        packet_ttl, packet_window_size, packet_mss
    );

    // Compare the packet fields with each signature
    for signature in signatures {
        if packet_ttl == signature.ittl && packet_window_size == signature.window {
            println!("Packet TTL: {}", signature.ittl);
            println!("Packet Window Size: {}", signature.window);
            return Some(signature);
        }
    }

    None
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

// Helper function to extract all TCP options from a TCP packet
/*fn extract_tcp_options(tcp_packet: &TcpPacket) -> Vec<TcpOption> {
    let mut options = Vec::new();

    // Iterate over all TCP options and collect them
    for option in tcp_packet.get_options_iter() {
        options.push(option);
    }

    options
}*/

// Function to handle IPv4 packets
pub fn handle_ipv4_packet(packet: Ipv4Packet, signatures: &Vec<TcpSignature>) {
    let tcp_packet = TcpPacket::new(packet.payload()).unwrap();

    let tcp_signature: Option<&TcpSignature> =
        match_packet_to_fingerprint(&packet, &tcp_packet, signatures);

    let tcp_package = TcpPackage {
        client: format!("{}/{}", packet.get_source(), tcp_packet.get_source()),
        os: Some("".to_string()),
        dist: 64i64 - packet.get_ttl() as i64,
        params: String::from("none"),
        raw_sig: tcp_signature
            .map(|sig| sig.sig.clone())
            .unwrap_or_else(|| "Unknown sig".to_string()),
    };

    println!("{}", tcp_package);
}
