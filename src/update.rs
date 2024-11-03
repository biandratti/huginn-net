use std::time::{SystemTime, UNIX_EPOCH};

const MIN_TWAIT: u64 = 1000; // Minimum time wait in milliseconds (1 second)
const MAX_TWAIT: u64 = 24 * 60 * 60 * 1000; // Maximum time wait in milliseconds (24 hours)

const MIN_TSCALE: f64 = 0.1;
const MAX_TSCALE: f64 = 1000.0;

//TODO: rename to uptime
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
/// Process the TCP packet to extract an Update, if conditions are met
/// Process the TCP packet to extract an Update, if conditions are met
fn get_update(
    timestamp_option: Option<u32>,
    last_syn_ts: u32,
    last_syn_recv_ms: u64,
) -> Option<Update> {
    println!("start get_update");

    // Return None if no timestamp option was found
    let packet_ts1 = timestamp_option?;

    let now_ms = get_unix_time_ms().ok()?;
    println!("Current time in ms: now_ms = {}", now_ms);
    println!(
        "Last SYN received time in ms: last_syn_recv_ms = {}",
        last_syn_recv_ms
    );

    let ms_diff = now_ms.saturating_sub(last_syn_recv_ms);
    println!("ms_diff = {}", ms_diff);

    let ts_diff = packet_ts1.wrapping_sub(last_syn_ts);
    println!("last_syn_ts = {}", last_syn_ts);
    println!("packet_ts1 = {}", packet_ts1);
    println!("ts_diff = {}", ts_diff);

    // Adjusted condition to enforce a minimum difference
    if ms_diff < MIN_TWAIT || ms_diff > MAX_TWAIT || ts_diff <= 0 {
        println!("Condition failed: ms_diff or ts_diff out of bounds.");
        return None;
    }

    // Optionally, enforce a minimum delta to prevent processing duplicates
    if ms_diff == 0 && ts_diff == 0 {
        println!(
            "Condition failed: both ms_diff and ts_diff are zero (potential duplicate packet)."
        );
        return None;
    }

    let ffreq = ts_diff as f64 * 1000.0 / ms_diff as f64;

    if ffreq < MIN_TSCALE || ffreq > MAX_TSCALE {
        println!("Condition failed: ffreq out of bounds.");
        return None;
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

    Some(Update {
        days: up_min / 60 / 24,
        hours: (up_min / 60) % 24,
        min: up_min % 60,
        up_mod_days,
        freq,
    })
}

/// Attempt to extract an Update from a SYN packet's timestamp options.
pub fn extract_update(timestamp_option: Option<u32>) -> Option<Update> {
    if let Some(ts_val) = timestamp_option {
        if let Ok(last_syn_recv_ms) = get_unix_time_ms() {
            return get_update(timestamp_option, ts_val, last_syn_recv_ms);
        } else {
            println!("Failed to retrieve the current Unix time.");
        }
    } else {
        println!("Timestamp option not found in TCP packet.");
    }
    None
}
