use log::error;
use pnet::packet::tcp::TcpFlags::{ACK, SYN};
use pnet::packet::tcp::TcpPacket;
use std::time::{SystemTime, UNIX_EPOCH};

const MIN_TWAIT: u64 = 1000; // Minimum wait time in ms
const MAX_TWAIT: u64 = 24 * 60 * 60 * 1000; // Maximum wait time in ms (1 day)
const MIN_TSCALE: f64 = 0.1; // Minimum timestamp scale
const MAX_TSCALE: f64 = 1000.0; // Maximum timestamp scale

pub struct Update {
    pub days: u32,
    pub hours: u32,
    pub min: u32,
    pub up_mod_days: u32,
    pub freq: u32,
}

/// Extract the current Unix time in milliseconds
fn get_unix_time_ms() -> Result<u64, &'static str> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "Time error")
        .map(|duration| duration.as_millis() as u64)
}

/// Process the TCP packet to extract an Update, if conditions are met
fn get_update(
    tcp: &TcpPacket,
    last_syn_ts: u32,
    last_syn_recv_ms: u64,
) -> Option<Update> {
    // Extract the first timestamp option from the TCP options
    let packet_ts1 = tcp
        .get_options_raw()
        .chunks_exact(10)
        .find_map(|chunk| {
            if chunk[0] == 8 && chunk[1] == 10 {
                Some(u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]))
            } else {
                None
            }
        })?;

    // Calculate the time difference in milliseconds
    let now_ms = get_unix_time_ms().ok()?;
    let ms_diff = now_ms.saturating_sub(last_syn_recv_ms);
    let ts_diff = packet_ts1.wrapping_sub(last_syn_ts);

    // Check for timing and timestamp conditions
    if ms_diff < MIN_TWAIT || ms_diff > MAX_TWAIT || ts_diff < 5 {
        return None;
    }

    let ffreq = ts_diff as f64 * 1000.0 / ms_diff as f64;

    // Validate frequency range
    if ffreq < MIN_TSCALE || ffreq > MAX_TSCALE {
        return None;
    }

    // Round the frequency to a manageable level
    let freq = match ffreq as u32 {
        0 => 1,
        1..=10 => ffreq as u32,
        11..=50 => ((ffreq + 3.0) / 5.0).round() as u32 * 5,
        51..=100 => ((ffreq + 7.0) / 10.0).round() as u32 * 10,
        101..=500 => ((ffreq + 33.0) / 50.0).round() as u32 * 50,
        _ => ((ffreq + 67.0) / 100.0).round() as u32 * 100,
    };

    // Calculate the uptime in minutes and modulo days
    let up_min = packet_ts1 / freq / 60;
    let up_mod_days = 0xFFFFFFFF / (freq * 60 * 60 * 24);

    Some(Update {
        days: up_min / 60 / 24,
        hours: (up_min / 60) % 24,
        min: up_min % 60,
        up_mod_days,
        freq,
    })
}

/// Attempt to extract an Update from a SYN packet's timestamp options.
pub fn extract_update(tcp: &TcpPacket) -> Option<Update> {
    let flags: u8 = tcp.get_flags();

    // Check if it's a SYN packet without ACK (first in a handshake)
    if flags & SYN == SYN && flags & ACK == 0 {
        // Extract the initial SYN timestamp option
        let timestamp_option = tcp
            .get_options_raw()
            .chunks_exact(10)
            .find_map(|chunk| {
                if chunk[0] == 8 && chunk[1] == 10 {
                    Some(u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]))
                } else {
                    None
                }
            });

        if let Some(last_syn_ts) = timestamp_option {
            // Get current time in milliseconds since UNIX epoch
            if let Ok(last_syn_recv_ms) = get_unix_time_ms() {
                // Call get_update to compute the Update struct
                return get_update(tcp, last_syn_ts, last_syn_recv_ms);
            } else {
                println!("Failed to retrieve the current Unix time.");
                error!("Failed to retrieve the current Unix time.");
            }
        } else {
            println!("Timestamp option not found in TCP packet.");
            error!("Timestamp option not found in TCP packet.");
        }
    }
    None
}
