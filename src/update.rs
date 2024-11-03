use log::warn;
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

fn get_update(
    tcp: &TcpPacket,
    last_syn_ts: u32,
    last_syn_recv_ms: u64,
) -> Result<Update, &'static str> {
    let packet_ts1 = tcp
        .get_options_raw()
        .chunks_exact(10)
        .find_map(|chunk| {
            if chunk[0] == 8 && chunk[1] == 10 {
                Some(u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]))
            } else {
                None
            }
        })
        .ok_or("Timestamp option not found")?;

    // Get current time in milliseconds
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "Time error")?
        .as_millis() as u64;

    let ms_diff = now_ms - last_syn_recv_ms;
    let ts_diff = packet_ts1.wrapping_sub(last_syn_ts);

    if ms_diff < MIN_TWAIT || ms_diff > MAX_TWAIT || ts_diff < 5 {
        return Ok(Update {
            days: 0,
            hours: 0,
            min: 0,
            up_mod_days: 0,
            freq: 0,
        });
    }

    let ffreq = ts_diff as f64 * 1000.0 / ms_diff as f64;

    if ffreq < MIN_TSCALE || ffreq > MAX_TSCALE {
        return Ok(Update {
            days: 0,
            hours: 0,
            min: 0,
            up_mod_days: 0,
            freq: 0,
        });
    }

    let freq = match ffreq as u32 {
        0 => 1,
        1..=10 => ffreq as u32,
        11..=50 => ((ffreq + 3.0) / 5.0).round() as u32 * 5,
        51..=100 => ((ffreq + 7.0) / 10.0).round() as u32 * 10,
        101..=500 => ((ffreq + 33.0) / 50.0).round() as u32 * 50,
        _ => ((ffreq + 67.0) / 100.0).round() as u32 * 100,
    };

    let up_min = packet_ts1 / freq / 60;
    let up_mod_days = 0xFFFFFFFF / (freq * 60 * 60 * 24);

    Ok(Update {
        days: up_min / 60 / 24,
        hours: (up_min / 60) % 24,
        min: up_min % 60,
        up_mod_days,
        freq,
    })
}

pub fn extract_update(tcp: &TcpPacket, flags: u8) -> Option<Update> {
    if flags & SYN == SYN && flags & ACK == 0 {
        // Attempt to extract timestamp option and current time
        let timestamp_option = tcp.get_options_raw().chunks_exact(10).find_map(|chunk| {
            if chunk[0] == 8 && chunk[1] == 10 {
                Some(u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]))
            } else {
                None
            }
        });

        if let Some(last_syn_ts) = timestamp_option {
            match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(duration) => {
                    let last_syn_recv_ms = duration.as_millis() as u64;
                    match get_update(tcp, last_syn_ts, last_syn_recv_ms) {
                        Ok(update) => Some(update),
                        Err(e) => {
                            warn!("Error calculating update: {}", e);
                            None
                        }
                    }
                }
                Err(e) => {
                    warn!("Time error: {:?}", e);
                    None
                }
            }
        } else {
            warn!("Timestamp option not found in TCP packet");
            None
        }
    } else {
        None
    }
}
