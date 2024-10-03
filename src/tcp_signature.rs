use pnet::packet::tcp::TcpOption;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/**
* sig = ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass
**/
#[derive(Debug)]
pub struct TcpSignature {
    pub ver: char,               // Version: '4', '6', or '*'
    pub ittl: u8,                // Initial TTL
    pub olen: u8,                // Length of IP options
    pub mss: Option<u16>,        // Maximum Segment Size
    pub wsize: String,           // Window size (can be fixed or a formula like "mss*4")
    pub scale: Option<u8>,       // Window scaling factor
    pub options: Vec<TcpOption>, // Layout of TCP options
    pub quirks: Vec<Quirk>,      // List of quirks
    pub pclass: PayloadClass,    // Payload size classification
}

#[derive(Debug)]
pub enum Quirk {
    Df,         // "Don't Fragment" flag set
    IdPlus,     // DF set, but non-zero IPID
    IdMinus,    // DF not set, zero IPID
    Ecn,        // Explicit Congestion Notification
    ZeroPlus,   // "Must be zero" field not zero
    Flow,       // Non-zero IPv6 flow ID
    SeqZero,    // Sequence number is zero
    AckPlus,    // ACK number non-zero, but ACK flag not set
    AckZero,    // ACK number is zero, but ACK flag set
    UrgPtrPlus, // URG pointer non-zero, but URG flag not set
    UrgFlag,    // URG flag used
    PushFlag,   // PUSH flag used
    Ts1Zero,    // Own timestamp specified as zero
    Ts2Plus,    // Peer timestamp non-zero on initial SYN
    OptPlus,    // Trailing non-zero data in options segment
    ExWscale,   // Excessive window scaling factor (> 14)
    BadOpt,     // Malformed TCP options
}

#[derive(Debug)]
pub enum PayloadClass {
    Zero,    // Zero payload
    NonZero, // Non-zero payload
    Any,     // Any payload
}

impl TcpSignature {
    pub fn all() -> Vec<TcpSignature> {
        let path = Path::new("config/p0f.fp");

        let file = File::open(path).expect("Failed to open file");
        let reader = BufReader::new(file);

        let mut tcp_signatures = Vec::new();

        for line in reader.lines() {
            let line = line.expect("Failed to read line");
            if line.trim().is_empty() {
                continue; // Skip empty lines
            }

            // Parse the line into individual components
            let parts: Vec<&str> = line.split(':').collect();

            if parts.len() != 9 {
                eprintln!("Skipping invalid line: {}", line);
                continue;
            }

            let ver = parts[0].chars().next().unwrap_or('*'); // Default to '*' if not available
            let ittl = parts[1].parse::<u8>().unwrap_or_default();
            let olen = parts[2].parse::<u8>().unwrap_or_default();
            let mss = if parts[3] == "*" {
                None
            } else {
                Some(parts[3].parse::<u16>().unwrap_or_default())
            };
            let wsize = parts[4].to_string();
            let scale = if parts[5] == "*" {
                None
            } else {
                Some(parts[5].parse::<u8>().unwrap_or_default())
            };

            // Parse TCP options (you might need to modify this based on actual format)
            let options = parse_tcp_options(parts[6]);

            // Parse quirks
            let quirks = parse_quirks(parts[7]);

            // Parse payload class
            let pclass = match parts[8] {
                "0" => PayloadClass::Zero,
                "1" => PayloadClass::NonZero,
                _ => PayloadClass::Any,
            };

            let signature = TcpSignature {
                ver,
                ittl,
                olen,
                mss,
                wsize,
                scale,
                options,
                quirks,
                pclass,
            };

            tcp_signatures.push(signature);
        }

        tcp_signatures
    }
}

fn parse_tcp_options(option_str: &str) -> Vec<TcpOption> {
    let mut options = Vec::new();
    let option_parts: Vec<&str> = option_str.split(',').collect();

    for option in option_parts {
        match option {
            "mss" => {
                // Add TcpOption for MSS (this is just an example, you'll need to create the proper struct from pnet)
                // You may need to manually create a TcpOption instance or use pnet's methods for options.
            }
            _ => continue,
        }
    }

    options
}

fn parse_quirks(quirks_str: &str) -> Vec<Quirk> {
    let mut quirks = Vec::new();
    let quirk_parts: Vec<&str> = quirks_str.split(',').collect();

    for quirk in quirk_parts {
        match quirk {
            "df" => quirks.push(Quirk::Df),
            "id+" => quirks.push(Quirk::IdPlus),
            "id-" => quirks.push(Quirk::IdMinus),
            "ecn" => quirks.push(Quirk::Ecn),
            "zero+" => quirks.push(Quirk::ZeroPlus),
            "flow" => quirks.push(Quirk::Flow),
            "seq0" => quirks.push(Quirk::SeqZero),
            "ack+" => quirks.push(Quirk::AckPlus),
            "ack0" => quirks.push(Quirk::AckZero),
            "urgptr+" => quirks.push(Quirk::UrgPtrPlus),
            "urg" => quirks.push(Quirk::UrgFlag),
            "push" => quirks.push(Quirk::PushFlag),
            "ts1-0" => quirks.push(Quirk::Ts1Zero),
            "ts2+" => quirks.push(Quirk::Ts2Plus),
            "opt+" => quirks.push(Quirk::OptPlus),
            "exwscale" => quirks.push(Quirk::ExWscale),
            "badopt" => quirks.push(Quirk::BadOpt),
            _ => continue,
        }
    }

    quirks
}
