use crate::UptimeData;
use pnet::packet::tcp::TcpFlags::SYN;
use std::time::{SystemTime, UNIX_EPOCH};

const MIN_TWAIT: u64 = 25;
const MAX_TWAIT: u64 = 10 * 60 * 1000;
const TSTAMP_GRACE: u64 = 1000;
const MAX_TSCALE: f64 = 1000.0;
const MIN_TSCALE: f64 = 0.01;

pub struct Uptime {
    pub days: u32,
    pub hours: u32,
    pub min: u32,
    pub up_mod_days: u32,
    pub freq: u32,
}

fn get_unix_time_ms() -> u64 {
    let now = SystemTime::now();
    now.duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64
}

pub fn check_ts_tcp(
    uptime_data: &mut UptimeData, //TODO: I need to move this parameter here...
    to_server: bool,
    ts_val: u32,
    tcp_type: u8,
) -> Option<Uptime> {
    let last_syn_data = if tcp_type == SYN {
        uptime_data.client.as_ref()
    } else {
        uptime_data.server.as_ref()
    };
    let ms_diff = get_unix_time_ms().saturating_sub(last_syn_data?.recv_ms);
    let ts_diff = ts_val.saturating_sub(last_syn_data?.ts1);

    if ms_diff < MIN_TWAIT || ms_diff > MAX_TWAIT {
        return None;
    }

    if ts_diff < 5
        || (ms_diff < TSTAMP_GRACE && ts_diff.wrapping_neg() as u64 / 1000 < MAX_TSCALE as u64)
    {
        return None;
    }

    let ffreq = if ts_diff > ts_diff.wrapping_neg() {
        ts_diff.wrapping_neg() as f64 * -1000.0 / ms_diff as f64
    } else {
        ts_diff as f64 * 1000.0 / ms_diff as f64
    };

    if ffreq < MIN_TSCALE || ffreq > MAX_TSCALE {
        if tcp_type != SYN {
            if to_server {
                if let Some(client) = uptime_data.client.as_mut() {
                    client.ts1 = 1; // TODO -1?
                }
                // f.cli_tps = -1; // Mark as invalid frequency TODO: Set in None?
            } else {
                if let Some(server) = uptime_data.server.as_mut() {
                    server.ts1 = 1; // TODO -1?
                }
                // f.srv_tps = -1; TODO: Set in None?
            }
        }
        return None; //TODO: evaluate this condition...
    }

    let freq = match ffreq.round() as u32 {
        0 => 1,
        1..=10 => ffreq.round() as u32,
        11..=50 => ((ffreq.round() + 3.0) / 5.0).round() as u32 * 5,
        51..=100 => ((ffreq.round() + 7.0) / 10.0).round() as u32 * 10,
        101..=500 => ((ffreq.round() + 33.0) / 50.0).round() as u32 * 50,
        _ => ((ffreq.round() + 67.0) / 100.0).round() as u32 * 100,
    };

    let up_min = ts_val / freq / 60;
    let up_mod_days = 0xFFFFFFFF / (freq * 60 * 60 * 24);

    Some(Uptime {
        days: up_min / 60 / 24,
        hours: (up_min / 60) % 24,
        min: up_min % 60,
        up_mod_days,
        freq,
    })
}
