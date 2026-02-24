//! Raw TCP options parser.
//!
//! Provides [`parse_options_raw`] for decoding TCP options from raw bytes (TLV encoding, RFC 793).
//! Pair it with [`crate::ttl::calculate_ttl`] and [`crate::window_size::detect_win_multiplicator`]
//! to assemble a complete [`huginn_net_db::observable_signals::TcpObservation`].

use crate::tcp::TcpOption;
use pnet::packet::tcp::{TcpOptionNumbers::*, TcpOptionPacket};
use pnet::packet::{Packet, PacketSize};

/// Decoded TCP options extracted from a raw SYN packet.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedTcpOptions {
    /// Ordered list of options successfully parsed before any malformed entry.
    pub olayout: Vec<TcpOption>,
    /// Maximum Segment Size, if the MSS option was present.
    pub mss: Option<u16>,
    /// Window Scale factor, if the WS option was present.
    pub wscale: Option<u8>,
    /// `true` if a truncated or malformed option was encountered during parsing.
    /// `olayout`, `mss`, and `wscale` reflect only the options parsed *before* the bad entry.
    pub malformed: bool,
}

/// Parses raw TCP options bytes (TLV encoding, RFC 793) into layout, MSS, and wscale.
///
/// `buf` must be pre-trimmed to the valid option bytes length (i.e. `tcp_data_offset * 4 - 20`).
///
/// # Returns
/// `(olayout, mss, wscale)` where:
/// - `olayout` — ordered list of options found (used for fingerprint matching).
/// - `mss`     — Maximum Segment Size if the MSS option was present.
/// - `wscale`  — Window Scale factor if the WS option was present.
///
/// # Example
///
/// ```rust
/// use huginn_net_tcp::syn_options::parse_options_raw;
/// use huginn_net_tcp::tcp::TcpOption;
///
/// let options: &[u8] = &[
///     2, 4, 0x05, 0xb4,               // MSS = 1460
///     1,                              // NOP
///     3, 3, 6,                        // WS = 6
///     1, 1,                           // NOP NOP
///     8, 10, 0, 0, 0, 1, 0, 0, 0, 0,  // Timestamps
///     4, 2,                           // SACK permitted
/// ];
/// let parsed = parse_options_raw(options);
/// assert_eq!(parsed.mss, Some(1460));
/// assert_eq!(parsed.wscale, Some(6));
/// assert!(parsed.olayout.contains(&TcpOption::TS));
/// ```
pub fn parse_options_raw(buf: &[u8]) -> ParsedTcpOptions {
    let mut olayout: Vec<TcpOption> = Vec::new();
    let mut mss: Option<u16> = None;
    let mut wscale: Option<u8> = None;
    let mut malformed = false;
    let mut remaining = buf;

    while let Some(opt) = TcpOptionPacket::new(remaining) {
        let kind = opt.get_number();

        // TLV options (anything except EOL/NOP) declare a length that must fit in the buffer.
        if kind != EOL && kind != NOP && opt.packet_size() > remaining.len() {
            malformed = true;
            break;
        }

        remaining = &remaining[opt.packet_size().min(remaining.len())..];
        let data = opt.payload();

        match kind {
            EOL => {
                olayout.push(TcpOption::Eol(remaining.len() as u8));
                break;
            }
            NOP => olayout.push(TcpOption::Nop),
            MSS => {
                olayout.push(TcpOption::Mss);
                if data.len() >= 2 {
                    mss = Some(u16::from_be_bytes([data[0], data[1]]));
                }
            }
            WSCALE => {
                olayout.push(TcpOption::Ws);
                if let Some(&scale) = data.first() {
                    wscale = Some(scale);
                }
            }
            SACK_PERMITTED => olayout.push(TcpOption::Sok),
            SACK => olayout.push(TcpOption::Sack),
            TIMESTAMPS => olayout.push(TcpOption::TS),
            other => olayout.push(TcpOption::Unknown(other.0)),
        }
    }

    ParsedTcpOptions { olayout, mss, wscale, malformed }
}
