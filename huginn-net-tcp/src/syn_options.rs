//! Raw TCP options parser.
//!
//! Provides [`parse_options_raw`] for decoding TCP options from raw bytes (TLV encoding, RFC 793).
//! Pair it with [`crate::ttl::calculate_ttl`] and [`crate::window_size::detect_win_multiplicator`]
//! to assemble a complete [`huginn_net_db::observable_signals::TcpObservation`].

use crate::tcp::TcpOption;

/// Decoded TCP options extracted from a raw SYN packet.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedTcpOptions {
    /// Ordered list of options (used for fingerprint matching).
    pub olayout: Vec<TcpOption>,
    /// Maximum Segment Size, if the MSS option was present.
    pub mss: Option<u16>,
    /// Window Scale factor, if the WS option was present.
    pub wscale: Option<u8>,
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
    let mut i = 0usize;

    while i < buf.len() {
        match buf[i] {
            0 => {
                // EOL — all remaining bytes after the EOL marker are padding
                let padding = buf.len().saturating_sub(i).saturating_sub(1);
                olayout.push(TcpOption::Eol(padding as u8));
                break;
            }
            1 => {
                // NOP — single byte, no length field
                olayout.push(TcpOption::Nop);
                i = i.saturating_add(1);
            }
            kind => {
                // TLV option: kind (1B) + length (1B) + data (length-2 B)
                let len_idx = i.saturating_add(1);
                if len_idx >= buf.len() {
                    break;
                }
                let len = buf[len_idx] as usize;
                let end = i.saturating_add(len);
                if len < 2 || end > buf.len() {
                    break;
                }
                let data = &buf[i.saturating_add(2)..end];

                match kind {
                    2 => {
                        olayout.push(TcpOption::Mss);
                        if data.len() >= 2 {
                            mss = Some(u16::from_be_bytes([data[0], data[1]]));
                        }
                    }
                    3 => {
                        olayout.push(TcpOption::Ws);
                        if let Some(&scale) = data.first() {
                            wscale = Some(scale);
                        }
                    }
                    4 => olayout.push(TcpOption::Sok),
                    5 => olayout.push(TcpOption::Sack),
                    8 => olayout.push(TcpOption::TS),
                    n => olayout.push(TcpOption::Unknown(n)),
                }

                i = end;
            }
        }
    }

    ParsedTcpOptions { olayout, mss, wscale }
}
