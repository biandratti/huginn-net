use super::common::IpPort;
use std::fmt;
use std::fmt::Formatter;

/// Represents the role of the host in the connection for uptime tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UptimeRole {
    Client,
    Server,
}

impl fmt::Display for UptimeRole {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            UptimeRole::Client => write!(f, "client"),
            UptimeRole::Server => write!(f, "server"),
        }
    }
}

/// Holds uptime information derived from TCP timestamp analysis.
#[derive(Debug)]
pub struct UptimeOutput {
    pub source: IpPort,
    pub destination: IpPort,
    pub role: UptimeRole,
    pub days: u32,
    pub hours: u32,
    pub min: u32,
    pub up_mod_days: u32,
    pub freq: f64,
}

impl fmt::Display for UptimeOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let role_str = match self.role {
            UptimeRole::Client => "Client",
            UptimeRole::Server => "Server",
        };
        write!(
            f,
            "[TCP Uptime - {}] {}:{} → {}:{}\n\
              Uptime: {} days, {} hrs, {} min (modulo {} days)\n\
              Freq:   {:.2} Hz\n",
            role_str,
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
            self.days,
            self.hours,
            self.min,
            self.up_mod_days,
            self.freq,
        )
    }
}