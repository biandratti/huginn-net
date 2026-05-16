use super::observable::ObservableUptime;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

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

pub(super) fn get_unix_time_ms() -> Option<u64> {
    let now = SystemTime::now();
    now.duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis() as u64)
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
