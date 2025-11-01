use crate::observable::ObservableUptime;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::debug;
use ttl_cache::TtlCache;

// p0f-style constants for uptime calculation
const MIN_TWAIT: u64 = 25; // Minimum time interval (ms) - p0f value
const MAX_TWAIT: u64 = 600000; // Maximum time interval (ms) - 10 minutes
const MIN_TS_DIFF: u32 = 5; // Minimum timestamp difference (ticks) - p0f value
const TSTAMP_GRACE: u64 = 100; // Tolerance for timestamps going backward (ms) - p0f value
const MAX_FINAL_HZ: f64 = 1500.0; // Maximum frequency (Hz)
const MIN_FINAL_HZ: f64 = 1.0; // Minimum frequency (Hz)
const GUESS_HZ_1K: f64 = 1000.0; // Common frequency guess: 1000 Hz
const GUESS_HZ_100: f64 = 100.0; // Common frequency guess: 100 Hz
const GUESS_TOLERANCE: f64 = 0.10; // Tolerance for frequency guessing

// Connection tracking cache TTL
const CONNECTION_CACHE_TTL_SECS: u64 = 30; // Time-to-live for cached connection data (seconds)

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub struct Connection {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

/// Connection tracking key that includes direction.
/// This ensures client and server timestamps are tracked separately.
#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub struct ConnectionKey {
    /// The connection tuple
    pub connection: Connection,
    /// True if this is tracking the client (src in original packet)
    pub is_client: bool,
}

/// TCP timestamp information for a single packet
#[derive(Debug, Clone)]
pub struct TcpTimestamp {
    /// Timestamp value (TSval) from TCP option
    pub ts_val: u32,
    /// Time when packet was received (ms since epoch)
    pub recv_time_ms: u64,
    /// Flag to indicate if frequency calculation failed (p0f equivalent: FrequencyState::Invalid)
    pub is_bad_frequency: bool,
}

impl TcpTimestamp {
    pub fn new(ts_val: u32, recv_time_ms: u64) -> Self {
        Self { ts_val, recv_time_ms, is_bad_frequency: false }
    }

    pub fn now(ts_val: u32) -> Self {
        Self { ts_val, recv_time_ms: get_unix_time_ms().unwrap_or(0), is_bad_frequency: false }
    }

    /// Create a marker timestamp indicating bad frequency (p0f equivalent: FrequencyState::Invalid)
    pub fn bad_frequency_marker() -> Self {
        Self { ts_val: 0, recv_time_ms: 0, is_bad_frequency: true }
    }
}

/// Represents the state of a frequency calculation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrequencyState {
    /// Frequency not yet calculated (waiting for second packet)
    NotCalculated,
    /// Frequency calculation failed or is invalid
    Invalid,
    /// Valid frequency in Hz
    Valid(u32),
}

impl FrequencyState {
    /// Returns `true` if the frequency state is valid
    pub fn is_valid(&self) -> bool {
        matches!(self, FrequencyState::Valid(_))
    }

    /// Returns `true` if the frequency state is invalid
    pub fn is_invalid(&self) -> bool {
        matches!(self, FrequencyState::Invalid)
    }

    pub fn value(&self) -> Option<u32> {
        match self {
            FrequencyState::Valid(freq) => Some(*freq),
            _ => None,
        }
    }
}

/// Uptime tracking information for a host
#[derive(Debug, Clone)]
pub struct UptimeTracker {
    /// Last SYN timestamp (for client tracking)
    pub last_syn: Option<TcpTimestamp>,
    /// Last SYN+ACK timestamp (for server tracking)  
    pub last_syn_ack: Option<TcpTimestamp>,
    /// Client frequency state
    pub cli_freq: FrequencyState,
    /// Server frequency state
    pub srv_freq: FrequencyState,
    /// Last calculated uptime information
    pub last_uptime: Option<ObservableUptime>,
}

impl UptimeTracker {
    pub fn new() -> Self {
        Self {
            last_syn: None,
            last_syn_ack: None,
            cli_freq: FrequencyState::NotCalculated,
            srv_freq: FrequencyState::NotCalculated,
            last_uptime: None,
        }
    }

    /// Mark client frequency as bad/invalid
    pub fn mark_client_frequency_bad(&mut self) {
        self.cli_freq = FrequencyState::Invalid;
    }

    /// Mark server frequency as bad/invalid
    pub fn mark_server_frequency_bad(&mut self) {
        self.srv_freq = FrequencyState::Invalid;
    }

    /// Check if client frequency is valid
    pub fn has_valid_client_frequency(&self) -> bool {
        self.cli_freq.is_valid()
    }

    /// Check if server frequency is valid
    pub fn has_valid_server_frequency(&self) -> bool {
        self.srv_freq.is_valid()
    }
}

impl Default for UptimeTracker {
    fn default() -> Self {
        Self::new()
    }
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

/// Smart frequency rounding following p0f methodology
/// This function rounds frequencies to common OS values based on ranges
fn round_frequency_p0f_style(freq: f64) -> u32 {
    let freq = freq as u32;

    match freq {
        0 => 1,         // Special case: 0 Hz -> 1 Hz
        1..=10 => freq, // No rounding for very low frequencies
        11..=50 => freq.saturating_add(3).saturating_div(5).saturating_mul(5), // Round to multiples of 5: 11->10, 13->15, 18->20
        51..=100 => freq.saturating_add(7).saturating_div(10).saturating_mul(10), // Round to multiples of 10: 51->50, 55->60, 99->100
        101..=500 => freq
            .saturating_add(33)
            .saturating_div(50)
            .saturating_mul(50), // Round to multiples of 50: 101->100, 125->150, 248->250
        _ => freq
            .saturating_add(67)
            .saturating_div(100)
            .saturating_mul(100), // Round to multiples of 100: 501->500, 650->700, 997->1000
    }
}

/// Calculate frequency between two timestamps with p0f-style backward handling
fn calculate_frequency_p0f_style(
    current: &TcpTimestamp,
    reference: &TcpTimestamp,
) -> Result<f64, String> {
    // Calculate time and timestamp differences
    let ms_diff = current.recv_time_ms.saturating_sub(reference.recv_time_ms);
    let ts_diff = current.ts_val.wrapping_sub(reference.ts_val);

    // Validate time interval
    if ms_diff < MIN_TWAIT {
        return Err(format!("Time interval too short: {ms_diff}ms < {MIN_TWAIT}ms"));
    }
    if ms_diff > MAX_TWAIT {
        return Err(format!("Time interval too long: {ms_diff}ms > {MAX_TWAIT}ms"));
    }

    // First, detect if timestamp went backward (p0f-style detection)
    let is_backward = ts_diff > !ts_diff;

    if is_backward {
        // Timestamp went backward
        let inverted_diff = !ts_diff;

        // Validate minimum timestamp difference for backward movement
        if inverted_diff < MIN_TS_DIFF {
            return Err(format!(
                "Backward timestamp difference too small: {inverted_diff} ticks < {MIN_TS_DIFF} ticks (MIN_TS_DIFF)"
            ));
        }

        // p0f validation: reject if within grace period AND backward amount is too large
        // Formula: (~ts_diff) / 1000 < MAX_TSCALE / TSTAMP_GRACE
        // This rejects backwards movements that would imply unreasonably high frequencies
        if ms_diff < TSTAMP_GRACE {
            let max_backward_ticks = (MAX_FINAL_HZ / TSTAMP_GRACE as f64) * 1000.0;
            if (inverted_diff as f64) > max_backward_ticks {
                return Err(format!(
                    "Backward timestamp too large within grace period: {inverted_diff} ticks > {max_backward_ticks:.0} max"
                ));
            }
        }
    } else {
        // Forward movement - validate minimum difference
        if ts_diff < MIN_TS_DIFF {
            return Err(format!(
                "Timestamp difference too small: {ts_diff} ticks < {MIN_TS_DIFF} ticks (MIN_TS_DIFF)"
            ));
        }
    }

    // Calculate frequency with backward timestamp handling
    let effective_ms_diff = ms_diff.max(1);
    let raw_freq = if ts_diff > !ts_diff {
        // Timestamp went backward - use inverted difference
        let inverted_diff = !ts_diff;
        (inverted_diff as f64 * 1000.0) / (effective_ms_diff as f64)
    } else {
        // Normal forward progression
        (ts_diff as f64 * 1000.0) / (effective_ms_diff as f64)
    };

    // Validate frequency range
    if !(MIN_FINAL_HZ..=MAX_FINAL_HZ).contains(&raw_freq) {
        return Err(format!(
            "Frequency out of valid range: {raw_freq:.2} Hz (valid: {MIN_FINAL_HZ}-{MAX_FINAL_HZ} Hz), ms_diff={ms_diff}, ts_diff={ts_diff}"
        ));
    }

    Ok(raw_freq)
}

/// New improved uptime calculation function using UptimeTracker
pub fn calculate_uptime_improved(
    tracker: &mut UptimeTracker,
    ts_val: u32,
    from_client: bool,
) -> Option<ObservableUptime> {
    let current_ts = TcpTimestamp::now(ts_val);

    if from_client {
        // Store SYN timestamp for client
        tracker.last_syn = Some(current_ts);
        return None; // SYN packets don't calculate uptime
    } else {
        // This is a server response (SYN+ACK or ACK)
        // Try to calculate uptime using stored SYN timestamp

        if let Some(ref syn_ts) = tracker.last_syn {
            // Check if we already have a valid client frequency
            if let Some(freq_hz) = tracker.cli_freq.value() {
                // Use existing frequency to calculate uptime
                let uptime_info = calculate_uptime_from_frequency(ts_val, freq_hz as f64);
                tracker.last_uptime = Some(uptime_info.clone());
                return Some(uptime_info);
            }

            // Check if client frequency is marked as bad
            if tracker.cli_freq.is_invalid() {
                return None;
            }

            // Try to calculate new frequency
            match calculate_frequency_p0f_style(&current_ts, syn_ts) {
                Ok(raw_freq) => {
                    // Apply intelligent rounding
                    let final_freq = if let Some(freq) =
                        guess_frequency(raw_freq, GUESS_HZ_1K, GUESS_TOLERANCE)
                    {
                        freq
                    } else if let Some(freq) =
                        guess_frequency(raw_freq, GUESS_HZ_100, GUESS_TOLERANCE)
                    {
                        freq
                    } else {
                        round_frequency_p0f_style(raw_freq) as f64
                    };

                    // Store the calculated frequency
                    tracker.cli_freq = FrequencyState::Valid(final_freq as u32);

                    // Calculate uptime
                    let uptime_info = calculate_uptime_from_frequency(ts_val, final_freq);
                    tracker.last_uptime = Some(uptime_info.clone());

                    return Some(uptime_info);
                }
                Err(_) => {
                    // Mark frequency as bad to avoid repeated attempts
                    tracker.mark_client_frequency_bad();
                    return None;
                }
            }
        }
    }

    None
}

/// Calculate uptime from timestamp and known frequency
fn calculate_uptime_from_frequency(ts_val: u32, freq_hz: f64) -> ObservableUptime {
    let uptime_seconds = ts_val as f64 / freq_hz;
    let days = (uptime_seconds / (24.0 * 3600.0)) as u32;
    let hours = ((uptime_seconds % (24.0 * 3600.0)) / 3600.0) as u32;
    let minutes = ((uptime_seconds % 3600.0) / 60.0) as u32;

    // Calculate wrap-around period
    let up_mod_days = (u32::MAX as f64 / (freq_hz * 60.0 * 60.0 * 24.0)) as u32;

    ObservableUptime { days, hours, min: minutes, up_mod_days, freq: freq_hz }
}

pub fn check_ts_tcp(
    connection_tracker: &mut TtlCache<ConnectionKey, TcpTimestamp>,
    connection: &Connection,
    from_client: bool,
    ts_val: u32,
) -> (Option<ObservableUptime>, Option<ObservableUptime>) {
    // Create a key that identifies this endpoint's timestamps
    // Client and server timestamps are tracked separately
    let tracking_key = ConnectionKey { connection: connection.clone(), is_client: from_client };

    // Create TcpTimestamp for current packet
    let current_ts = TcpTimestamp::now(ts_val);

    if from_client {
        // This is a client packet (SYN or ACK)
        // Check if we have a previous timestamp from the same client
        if let Some(reference_ts) = connection_tracker.get(&tracking_key) {
            // p0f: if frequency is marked as bad (equivalent to FrequencyState::Invalid), don't recalculate
            if reference_ts.is_bad_frequency {
                debug!(
                    "Client frequency already marked as bad for {}:{}, skipping",
                    connection.src_ip, connection.src_port
                );
                return (None, None);
            }

            // We have a previous packet from this client, calculate uptime
            debug!(
                "Client packet: {}:{} -> {}:{}, ref_ts={}, current_ts={}, diff={}",
                connection.src_ip,
                connection.src_port,
                connection.dst_ip,
                connection.dst_port,
                reference_ts.ts_val,
                ts_val,
                ts_val.wrapping_sub(reference_ts.ts_val)
            );

            match calculate_frequency_p0f_style(&current_ts, reference_ts) {
                Ok(raw_freq) => {
                    // Apply intelligent rounding
                    let final_freq = if let Some(freq) =
                        guess_frequency(raw_freq, GUESS_HZ_1K, GUESS_TOLERANCE)
                    {
                        freq
                    } else if let Some(freq) =
                        guess_frequency(raw_freq, GUESS_HZ_100, GUESS_TOLERANCE)
                    {
                        freq
                    } else {
                        round_frequency_p0f_style(raw_freq) as f64
                    };

                    // Calculate uptime using the improved method
                    let uptime_info = calculate_uptime_from_frequency(ts_val, final_freq);

                    debug!(
                        "CLIENT Uptime detected: {:.2} Hz -> {} Hz, {} days {} hrs {} min (mod {} days)",
                        raw_freq, final_freq, uptime_info.days, uptime_info.hours, uptime_info.min, uptime_info.up_mod_days
                    );

                    return (Some(uptime_info), None);
                }
                Err(error) => {
                    debug!("Client uptime calculation failed: {}", error);

                    // p0f: Mark frequency as bad to avoid recalculation (equivalent to FrequencyState::Invalid)
                    // Store a bad frequency marker
                    connection_tracker.insert(
                        tracking_key.clone(),
                        TcpTimestamp::bad_frequency_marker(),
                        Duration::new(CONNECTION_CACHE_TTL_SECS, 0),
                    );
                }
            }
        } else {
            // First packet from this client, store it
            debug!(
                "Storing first client packet: {}:{} -> {}:{}, ts_val={}",
                connection.src_ip,
                connection.src_port,
                connection.dst_ip,
                connection.dst_port,
                ts_val
            );
            connection_tracker.insert(
                tracking_key,
                current_ts,
                Duration::new(CONNECTION_CACHE_TTL_SECS, 0),
            );
        }
    } else {
        // This is a server packet (SYN+ACK or ACK)
        // Check if we have a previous timestamp from the same server
        if let Some(reference_ts) = connection_tracker.get(&tracking_key) {
            // p0f: if frequency is marked as bad (equivalent to FrequencyState::Invalid), don't recalculate
            if reference_ts.is_bad_frequency {
                debug!(
                    "Server frequency already marked as bad for {}:{}, skipping",
                    connection.src_ip, connection.src_port
                );
                return (None, None);
            }

            // We have a previous packet from this server, calculate uptime
            debug!(
                "Server packet: {}:{} -> {}:{}, ref_ts={}, current_ts={}, diff={}",
                connection.src_ip,
                connection.src_port,
                connection.dst_ip,
                connection.dst_port,
                reference_ts.ts_val,
                ts_val,
                ts_val.wrapping_sub(reference_ts.ts_val)
            );

            match calculate_frequency_p0f_style(&current_ts, reference_ts) {
                Ok(raw_freq) => {
                    // Apply intelligent rounding
                    let final_freq = if let Some(freq) =
                        guess_frequency(raw_freq, GUESS_HZ_1K, GUESS_TOLERANCE)
                    {
                        freq
                    } else if let Some(freq) =
                        guess_frequency(raw_freq, GUESS_HZ_100, GUESS_TOLERANCE)
                    {
                        freq
                    } else {
                        round_frequency_p0f_style(raw_freq) as f64
                    };

                    // Calculate uptime using the improved method
                    let uptime_info = calculate_uptime_from_frequency(ts_val, final_freq);

                    debug!(
                        "SERVER Uptime detected: {:.2} Hz -> {} Hz, {} days {} hrs {} min (mod {} days)",
                        raw_freq, final_freq, uptime_info.days, uptime_info.hours, uptime_info.min, uptime_info.up_mod_days
                    );

                    return (None, Some(uptime_info));
                }
                Err(error) => {
                    debug!("Server uptime calculation failed: {}", error);

                    // p0f: Mark frequency as bad to avoid recalculation
                    // Store a bad frequency marker
                    connection_tracker.insert(
                        tracking_key.clone(),
                        TcpTimestamp::bad_frequency_marker(),
                        Duration::new(CONNECTION_CACHE_TTL_SECS, 0),
                    );
                }
            }
        } else {
            // First packet from this server, store it
            debug!(
                "Storing first server packet: {}:{} -> {}:{}, ts_val={}",
                connection.src_ip,
                connection.src_port,
                connection.dst_ip,
                connection.dst_port,
                ts_val
            );
            connection_tracker.insert(
                tracking_key,
                current_ts,
                Duration::new(CONNECTION_CACHE_TTL_SECS, 0),
            );
        }
    }

    (None, None)
}
