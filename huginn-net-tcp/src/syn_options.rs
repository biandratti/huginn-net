//! TCP observation builder from raw bytes.
//!
//! The existing [`crate::tcp_process`] module builds [`TcpObservation`]s via `pnet`,
//! which requires a full parsed packet. This module provides [`observation_from_raw`]

use crate::tcp::{IpVersion, PayloadSize, TcpOption};
use huginn_net_db::observable_signals::TcpObservation;
use huginn_net_db::tcp::Quirk;

/// Build a [`TcpObservation`] from raw SYN packet fields.
///
/// This is the entry point for OS matching via [`crate::SignatureMatcher`].
/// It combines [`parse_options_raw`] with the library's TTL normalisation
/// and window-size detection to produce a complete observation.
///
/// # Parameters
///
/// | Parameter    | Description |
/// |--------------|-------------|
/// | `version`    | IP version (`V4` or `V6`). |
/// | `ip_hdr_len` | IP header length in bytes (20 for plain IPv4, 40 for IPv6, more with options). |
/// | `raw_ttl`    | IP TTL / hop limit as read from the packet (host byte order). |
/// | `window`     | TCP window size in **host byte order**. |
/// | `olen`       | IP options / extension header length in bytes. Pass `0` when unavailable. |
/// | `options`    | Raw TCP options bytes, already trimmed to `optlen` bytes. |
/// | `quirks`     | Observed IP/TCP quirks. Pass `vec![]` when unavailable. |
/// | `pclass`     | Payload size classification. Use [`PayloadSize::Zero`] for SYN packets. |
/// ```
#[allow(clippy::too_many_arguments)]
pub fn observation_from_raw(
    version: IpVersion,
    ip_hdr_len: u16,
    raw_ttl: u8,
    window: u16,
    olen: u8,
    options: &[u8],
    quirks: Vec<Quirk>,
    pclass: PayloadSize,
) -> TcpObservation {
    let (olayout, mss, wscale) = parse_options_raw(options);
    let ittl = crate::ttl::calculate_ttl(raw_ttl);
    let wsize = crate::window_size::detect_win_multiplicator(
        window,
        mss.unwrap_or(0),
        ip_hdr_len,
        olayout.contains(&TcpOption::TS),
        &version,
    );
    TcpObservation { version, ittl, olen, mss, wsize, wscale, olayout, quirks, pclass }
}

/// Parses raw TCP options bytes (TLV encoding, RFC 793) into layout, MSS, and wscale.
/// `buf` must be pre-trimmed to the valid option bytes length.
pub(crate) fn parse_options_raw(buf: &[u8]) -> (Vec<TcpOption>, Option<u16>, Option<u8>) {
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

    (olayout, mss, wscale)
}
