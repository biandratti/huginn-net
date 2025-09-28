use crate::observable::ObservableUptime;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::debug;
use ttl_cache::TtlCache;

// const MIN_TWAIT: u64 = 0;
const MAX_TWAIT: u64 = 600000;
const MAX_FINAL_HZ: f64 = 1500.0;
const MIN_FINAL_HZ: f64 = 1.0;
const GUESS_HZ_1K: f64 = 1000.0;
const GUESS_HZ_100: f64 = 100.0;
const GUESS_TOLERANCE: f64 = 0.10;

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub struct Connection {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

pub struct SynData {
    ts1: u32,
    recv_ms: u64,
}

fn get_unix_time_ms() -> Option<u64> {
    let now = SystemTime::now();
    now.duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis() as u64)
}

fn guess_frequency(raw_freq: f64, base_guess: f64, tolerance: f64) -> Option<f64> {
    if raw_freq <= 0.0 || base_guess <= 0.0 || !raw_freq.is_finite() {
        return None;
    }
    let multiplier = (raw_freq / base_guess).round();
    if multiplier <= 0.0 {
        return None;
    }
    let normalized = raw_freq / multiplier;
    if (normalized - base_guess).abs() <= base_guess * tolerance {
        Some(base_guess)
    } else {
        None
    }
}

pub fn check_ts_tcp(
    connection_tracker: &mut TtlCache<Connection, SynData>,
    connection: &Connection,
    from_client: bool,
    ts_val: u32,
) -> Option<ObservableUptime> {
    debug!(
        "Processing packet - from_client: {}, ts_val: {}",
        from_client, ts_val
    );

    let syn_data: Option<SynData> = if !from_client {
        let client_connection = Connection {
            src_ip: connection.dst_ip,
            src_port: connection.dst_port,
            dst_ip: connection.src_ip,
            dst_port: connection.src_port,
        };
        debug!("Server response - looking for client SYN data");
        let data = connection_tracker.remove(&client_connection);
        if data.is_none() {
            debug!("No SYN data found in connection_tracker for connection");
        }
        data
    } else {
        debug!("Client SYN - storing timestamp data");
        if let Some(recv_ms) = get_unix_time_ms() {
            connection_tracker.insert(
                connection.clone(),
                SynData {
                    ts1: ts_val,
                    recv_ms,
                },
                Duration::new(60, 0),
            );
        } else {
            debug!("Failed to get current time, skipping SYN data storage");
        }
        None
    };

    let last_syn_data = match syn_data {
        Some(data) => data,
        None => {
            debug!("No SYN data available, skipping uptime calculation");
            return None;
        }
    };

    let current_time = match get_unix_time_ms() {
        Some(time) => time,
        None => {
            debug!("Failed to get current time for uptime calculation");
            return None;
        }
    };
    let ms_diff = current_time.saturating_sub(last_syn_data.recv_ms);

    if ms_diff > MAX_TWAIT {
        debug!(
            "Time difference {}ms exceeds MAX_TWAIT {}ms",
            ms_diff, MAX_TWAIT
        );
        return None;
    }

    let effective_ms_diff = ms_diff.max(1); // Use 1ms if ms_diff is 0

    let ts_diff = ts_val.wrapping_sub(last_syn_data.ts1);
    if ts_diff == 0 && effective_ms_diff <= 1 {
        debug!("Timestamp difference is zero and effective time difference is <= 1ms, skipping");
        return None;
    }

    debug!(
        "Time differences - measured ms_diff: {}ms, effective ms_diff: {}ms, ts_diff: {} ticks",
        ms_diff, effective_ms_diff, ts_diff
    );
    debug!(
        "Original timestamps - current: {}, original: {}",
        ts_val, last_syn_data.ts1
    );
    debug!(
        "Time values - current: {}ms, original: {}ms",
        current_time, last_syn_data.recv_ms
    );

    let raw_freq = (ts_diff as f64 * 1000.0) / (effective_ms_diff as f64);
    debug!("Raw frequency (Hz): {:.2}", raw_freq);

    if raw_freq <= 0.0 || !raw_freq.is_finite() {
        debug!("Invalid or non-finite raw frequency {:.2} Hz", raw_freq);
        return None;
    }

    let final_freq_hz: f64;
    if let Some(freq) = guess_frequency(raw_freq, GUESS_HZ_1K, GUESS_TOLERANCE) {
        debug!(
            "Guessed base frequency {:.2} Hz from raw {:.2} Hz",
            freq, raw_freq
        );
        final_freq_hz = freq;
    } else if let Some(freq) = guess_frequency(raw_freq, GUESS_HZ_100, GUESS_TOLERANCE) {
        debug!(
            "Guessed base frequency {:.2} Hz from raw {:.2} Hz",
            freq, raw_freq
        );
        final_freq_hz = freq;
    } else if (MIN_FINAL_HZ..=MAX_FINAL_HZ).contains(&raw_freq) {
        debug!(
            "Raw frequency is within normal range ({:.1} Hz - {:.1} Hz). Using rounded value.",
            MIN_FINAL_HZ, MAX_FINAL_HZ
        );
        final_freq_hz = raw_freq.round();
    } else {
        debug!(
            "Could not determine a reliable frequency from raw value {:.2} Hz. Discarding.",
            raw_freq
        );
        return None;
    };

    debug!("Using final frequency (Hz): {:.2}", final_freq_hz);

    let freq = final_freq_hz;

    let wrap_secs = (u32::MAX as f64) / final_freq_hz;
    let up_mod_days = (wrap_secs / (24.0 * 3600.0)).round() as u32;

    if !(1..=300).contains(&up_mod_days) {
        debug!(
            "Calculated modulo days ({}) seems unreasonable. Discarding.",
            up_mod_days
        );
        return None;
    }
    debug!("Modulo days: {}", up_mod_days);

    let uptime_secs_from_tsval = ts_val as f64 / final_freq_hz;
    if uptime_secs_from_tsval > wrap_secs * 1.1 {
        debug!(
            "Uptime from ts_val ({:.0}s) significantly exceeds wrap-around time ({:.0}s).",
            uptime_secs_from_tsval, wrap_secs
        );
    }
    let total_secs_from_tsval = uptime_secs_from_tsval as u64;
    let days = total_secs_from_tsval / (24 * 3600);
    let hours = (total_secs_from_tsval % (24 * 3600)) / 3600;
    let minutes = (total_secs_from_tsval % 3600) / 60;

    debug!(
        "Uptime based on ts_val (MAY BE INACCURATE) - days: {}, hours: {}, minutes: {}",
        days, hours, minutes
    );

    Some(ObservableUptime {
        days: days as u32,
        hours: hours as u32,
        min: minutes as u32,
        up_mod_days,
        freq,
    })
}
