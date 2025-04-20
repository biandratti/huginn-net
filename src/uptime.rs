use log::info;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use ttl_cache::TtlCache;

const MIN_TWAIT: u64 = 1;
const MAX_TWAIT: u64 = 600000;
const TSTAMP_GRACE: u64 = 1000;
const MAX_TSCALE: f64 = 1000.0;
const MIN_TSCALE: f64 = 1.0;
const HZ_SCALE: f64 = 1.0;

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

pub struct ObservableUptime {
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
    cache: &mut TtlCache<Connection, SynData>,
    connection: &Connection,
    from_client: bool,
    ts_val: u32,
) -> Option<ObservableUptime> {
    info!(
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
        info!("Server response - looking for client SYN data");
        let data = cache.remove(&client_connection);
        if data.is_none() {
            info!("No SYN data found in cache for connection");
        }
        data
    } else {
        info!("Client SYN - storing timestamp data");
        cache.insert(
            connection.clone(),
            SynData {
                ts1: ts_val,
                recv_ms: get_unix_time_ms(),
            },
            Duration::new(60, 0),
        );
        None
    };

    let last_syn_data = match syn_data {
        Some(data) => data,
        None => {
            info!("No SYN data available, skipping uptime calculation");
            return None;
        }
    };

    let current_time = get_unix_time_ms();
    let ms_diff = current_time.saturating_sub(last_syn_data.recv_ms);

    let ts_diff = if ts_val >= last_syn_data.ts1 {
        ts_val - last_syn_data.ts1
    } else {
        (u32::MAX - last_syn_data.ts1) + ts_val + 1
    } as u64;

    info!(
        "Time differences - ms_diff: {}ms, ts_diff: {} ticks",
        ms_diff, ts_diff
    );
    info!(
        "Original timestamps - current: {}, original: {}",
        ts_val, last_syn_data.ts1
    );
    info!(
        "Time values - current: {}ms, original: {}ms",
        current_time, last_syn_data.recv_ms
    );

    if ms_diff > MAX_TWAIT || ms_diff < MIN_TWAIT {
        info!("Invalid time difference: {}ms", ms_diff);
        return None;
    }

    let raw_freq = (ts_diff as f64 * 1000.0) / (ms_diff as f64);
    info!("Raw frequency (Hz): {:.2}", raw_freq);

    let ffreq = raw_freq.min(MAX_TSCALE).max(MIN_TSCALE);
    info!("Adjusted frequency (Hz): {:.2}", ffreq);

    let freq = (ffreq * 100.0).round() as u32;

    let up_secs = ts_val as f64 / ffreq;
    let up_min = (up_secs / 60.0).round() as u64;

    let wrap_secs = (u32::MAX as f64) / ffreq;
    let up_mod_days = (wrap_secs / (24.0 * 60.0 * 60.0)).round() as u32;

    let days = up_min / (60 * 24);
    let hours = (up_min / 60) % 24;
    let minutes = up_min % 60;

    info!(
        "Calculated uptime - days: {}, hours: {}, minutes: {}",
        days, hours, minutes
    );
    info!("Modulo days: {}", up_mod_days);

    Some(ObservableUptime {
        days: days as u32,
        hours: hours as u32,
        min: minutes as u32,
        up_mod_days,
        freq,
    })
}
