use huginn_net_db::observable_signals::TcpObservation;

// Observable TCP signals
#[derive(Debug, Clone)]
pub struct ObservableTcp {
    /// Core matching data for fingerprinting
    pub matching: TcpObservation,
    // Additional fields for extended analysis could go here in the future
}

// Observable MTU signals
pub struct ObservableMtu {
    pub value: u16,
}

// Observable Uptime signals
pub struct ObservableUptime {
    pub days: u32,
    pub hours: u32,
    pub min: u32,
    pub up_mod_days: u32,
    pub freq: f64,
}
