use crate::tcp_signature::{TcpSignature, TcpOption};
use crate::tcp_package::TcpPackage;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::{ipv6::Ipv6Packet, tcp::{TcpPacket, TcpOptionPacket, TcpOptionNumbers}, Packet};

pub fn handle_ethernet_packet(packet: EthernetPacket) {
    match packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4_packet: Ipv4Packet = Ipv4Packet::new(packet.payload()).unwrap();
            if ipv4_packet.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Tcp {
                handle_ipv4_packet(ipv4_packet);
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
fn match_packet_to_fingerprint(ipv4_packet: &Ipv4Packet, tcp_packet: &TcpPacket) -> Option<String> {
    let signatures = vec![
        TcpSignature::linux_3_11_and_newer(),
        TcpSignature::linux_2_6_x(),
    ];

    // Extract relevant fields from the packet
    let packet_ttl = ipv4_packet.get_ttl();
    let tcp_mss = extract_mss(tcp_packet);
    let tcp_window = tcp_packet.get_window();
    let tcp_df = ipv4_packet.get_flags() & 0x2 != 0; // Check if the Don't Fragment (DF) flag is set
    let tcp_options = extract_tcp_options(tcp_packet);



    // Calculate option length
    let tcp_olen: u8 = tcp_options.iter().map(|option| {
        match option {
            TcpOption::Mss(_) => 4, // MSS option is 4 bytes (1 byte type + 1 byte length + 2 bytes value)
            TcpOption::SackPermitted => 2, // Sack Permitted is 2 bytes (1 byte type + 1 byte length)
            TcpOption::Timestamp(_, _) => 10, // Timestamp is 10 bytes
            TcpOption::Nop => 1, // NOP is 1 byte
            TcpOption::WindowScale(_) => 3, // Window Scale is 3 bytes (1 byte type + 1 byte length + 1 byte value)
        }
    }).sum::<usize>() as u8;

    let tcp_scale: u8 = tcp_options.iter().filter_map(|option| {
        if let TcpOption::WindowScale(s) = option {
            Some(*s)
        } else {
            None
        }
    }).next().unwrap_or(0); // Default to 0 if no Window Scale option found

    println!(
        "TTL: {}, MSS: {:?}, TCP Window: {}, DF: {}, TCP Options: {:?}, tcp olen: {}, tcp scale: {}",
        packet_ttl,
        tcp_mss,
        tcp_window,
        tcp_df,
        tcp_options,
        tcp_olen,
        tcp_scale
    );

    // Compare the packet with each signature
    for signature_group in signatures {
        for signature in signature_group {
            if packet_ttl == signature.ttl
                // && tcp_mss == signature.mss
                // && Some(tcp_window) == signature.window
                // && tcp_df == signature.df
                 && tcp_olen == signature.olen
                 && tcp_scale == signature.scale
                // && tcp_options_match(&tcp_options, &signature.options)
            {
                // If all conditions are met, return the signature's label
                return Some("Matched Linux signature".to_string()); // Update this with an appropriate label
            }
        }
    }

    None
}

// Function to extract MSS
fn extract_mss(tcp_packet: &TcpPacket) -> Option<u16> {
    for option in tcp_packet.get_options_iter() {
        if option.get_number() == TcpOptionNumbers::MSS {
            // MSS option value is stored in the payload of the option
            let payload = option.payload();
            if payload.len() == 2 {
                return Some(u16::from_be_bytes([payload[0], payload[1]]));
            }
        }
    }
    None
}

// Function to extract TCP options
fn extract_tcp_options(tcp_packet: &TcpPacket) -> Vec<TcpOption> {
    let mut options = Vec::new();
    for option in tcp_packet.get_options_iter() {
        match option.get_number() {
            TcpOptionNumbers::MSS => {
                if let Some(mss) = extract_mss_from_option(option) {
                    options.push(TcpOption::Mss(mss));
                }
            }
            TcpOptionNumbers::SACK_PERMITTED => {
                options.push(TcpOption::SackPermitted);
            }
            TcpOptionNumbers::TIMESTAMPS => {
                if let Some((ts_val, ts_echo)) = extract_timestamp_from_option(option) {
                    options.push(TcpOption::Timestamp(ts_val, ts_echo));
                }
            }
            TcpOptionNumbers::NOP => {
                options.push(TcpOption::Nop);
            }
            TcpOptionNumbers::WSCALE => {
                if let Some(ws) = extract_window_scale_from_option(option) {
                    options.push(TcpOption::WindowScale(ws));
                }
            }
            _ => {}
        }
    }
    options
}

// Function to extract MSS from TCP option
fn extract_mss_from_option(opt_packet: TcpOptionPacket) -> Option<u16> {
    let payload = opt_packet.payload();
    if payload.len() == 2 {
        return Some(u16::from_be_bytes([payload[0], payload[1]]));
    }
    None
}

// Function to extract timestamp from TCP option
fn extract_timestamp_from_option(opt_packet: TcpOptionPacket) -> Option<(u32, u32)> {
    let payload = opt_packet.payload();
    if payload.len() == 8 {
        let ts_val = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let ts_echo = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        return Some((ts_val, ts_echo));
    }
    None
}

// Function to extract window scale from TCP option
fn extract_window_scale_from_option(opt_packet: TcpOptionPacket) -> Option<u8> {
    let payload = opt_packet.payload();
    if payload.len() == 1 {
        return Some(payload[0]);
    }
    None
}

// Function to check if TCP options match
fn tcp_options_match(packet_options: &Vec<TcpOption>, signature_options: &Vec<TcpOption>) -> bool {
    packet_options == signature_options
}

// Function to handle IPv4 packets
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