use crate::observable::ObservableTcp;
use crate::tcp::Ttl;
use std::fmt;
use std::fmt::Formatter;

/// Represents the output from TCP analysis.
///
/// This struct contains various optional outputs that can be derived
/// from analyzing TCP packets.
#[derive(Debug)]
pub struct TcpAnalysisResult {
    /// Information derived from SYN packets.
    pub syn: Option<SynTCPOutput>,

    /// Information derived from SYN-ACK packets.
    pub syn_ack: Option<SynAckTCPOutput>,

    /// Information about the Maximum Transmission Unit (MTU).
    pub mtu: Option<MTUOutput>,

    /// Information about the client system uptime.
    pub client_uptime: Option<UptimeOutput>,

    /// Information about the server system uptime.
    pub server_uptime: Option<UptimeOutput>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IpPort {
    pub ip: std::net::IpAddr,
    pub port: u16,
}

impl IpPort {
    pub fn new(ip: std::net::IpAddr, port: u16) -> Self {
        Self { ip, port }
    }
}

/// Marker telling whether a fingerprint is a "specific" definition or a
/// "generic" fall-back. Equivalent to p0f's `s` / `g` label prefix but
/// expressed as a TCP-local enum so this crate stays decoupled from any
/// particular database format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OsKind {
    Specified,
    Generic,
}

impl fmt::Display for OsKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OsKind::Specified => "Specified",
            OsKind::Generic => "Generic",
        })
    }
}

/// Outcome of matching an observation against a fingerprint database.
///
/// Independent from any specific database type so that consumers of this
/// crate don't need to depend on `huginn-net-db`.
#[derive(Clone, Debug)]
pub enum MatchQuality {
    /// Successful match. Score is in `[0.0, 1.0]` with `1.0` being a
    /// perfect match and lower scores indicating fuzzier matches.
    Matched(f32),
    /// A matcher was attached but no signature matched the observation.
    NotMatched,
    /// No matcher was attached, so matching was skipped entirely.
    Disabled,
}

/// Represents an operative system.
///
/// Examples:
/// - `name: "Linux"`,   `family: Some("unix")`, `variant: Some("2.2.x-3.x")`, `kind: OsKind::Specified`
/// - `name: "Windows"`, `family: Some("win")`,  `variant: Some("NT kernel 6.x")`, `kind: OsKind::Specified`
#[derive(Debug, Clone)]
pub struct OperativeSystem {
    pub name: String,
    pub family: Option<String>,
    pub variant: Option<String>,
    pub kind: OsKind,
}

/// The operative system with the highest quality that matches the packet.
#[derive(Debug)]
pub struct OSQualityMatched {
    pub os: Option<OperativeSystem>,
    pub quality: MatchQuality,
}

/// Holds information derived from analyzing a TCP SYN packet (client initiation).
#[derive(Debug)]
pub struct SynTCPOutput {
    /// The source IP address and port of the client sending the SYN.
    pub source: IpPort,
    /// The destination IP address and port of the server receiving the SYN.
    pub destination: IpPort,
    /// The operative system with the highest quality that matches the SYN packet.
    pub os_matched: OSQualityMatched,
    /// The raw TCP signature extracted from the SYN packet.
    pub sig: ObservableTcp,
}

impl fmt::Display for SynTCPOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[TCP SYN] {}:{} → {}:{}\n\
              OS:     {}\n\
              Dist:   {}\n\
              Params: {}\n\
              Sig:    {}\n",
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
            self.os_matched.os.as_ref().map_or("???".to_string(), |os| {
                format!(
                    "{}/{}/{}",
                    os.name,
                    os.family.as_deref().unwrap_or("???"),
                    os.variant.as_deref().unwrap_or("??")
                )
            }),
            match self.sig.matching.ittl {
                Ttl::Distance(_, distance) => distance,
                Ttl::Bad(value) => value,
                Ttl::Value(value) => value,
                Ttl::Guess(value) => value,
            },
            self.os_matched
                .os
                .as_ref()
                .map_or("none".to_string(), |os| os.kind.to_string()),
            self.sig,
        )
    }
}

/// Holds information derived from analyzing a TCP SYN+ACK packet (server response).
#[derive(Debug)]
pub struct SynAckTCPOutput {
    /// The source IP address and port of the server sending the SYN+ACK.
    pub source: IpPort,
    /// The destination IP address and port of the client receiving the SYN+ACK.
    pub destination: IpPort,
    /// The operative system with the highest quality that matches the SYN+ACK packet.
    pub os_matched: OSQualityMatched,
    /// The raw TCP signature extracted from the SYN+ACK packet.
    pub sig: ObservableTcp,
}

impl fmt::Display for SynAckTCPOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[TCP SYN+ACK] {}:{} → {}:{}\n\
              OS:     {}\n\
              Dist:   {}\n\
              Params: {}\n\
              Sig:    {}\n",
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
            self.os_matched.os.as_ref().map_or("???".to_string(), |os| {
                format!(
                    "{}/{}/{}",
                    os.name,
                    os.family.as_deref().unwrap_or("???"),
                    os.variant.as_deref().unwrap_or("??")
                )
            }),
            match self.sig.matching.ittl {
                Ttl::Distance(_, distance) => distance,
                Ttl::Bad(value) => value,
                Ttl::Value(value) => value,
                Ttl::Guess(value) => value,
            },
            self.os_matched
                .os
                .as_ref()
                .map_or("none".to_string(), |os| os.kind.to_string()),
            self.sig,
        )
    }
}

#[derive(Debug)]
pub struct MTUQualityMatched {
    pub link: Option<String>,
    pub quality: MatchQuality,
}

/// Holds information about the estimated Maximum Transmission Unit (MTU) of a link.
#[derive(Debug)]
pub struct MTUOutput {
    /// The source IP address and port (usually the client).
    pub source: IpPort,
    /// The destination IP address and port (usually the server).
    pub destination: IpPort,
    /// An estimated link type (e.g., "Ethernet", "PPPoE") based on the calculated MTU.
    pub link: MTUQualityMatched,
    /// The calculated Maximum Transmission Unit (MTU) value in bytes.
    pub mtu: u16,
}

impl fmt::Display for MTUOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[TCP MTU] {}:{} → {}:{}\n\
              Link:   {}\n\
              MTU:    {}\n",
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
            self.link
                .link
                .as_ref()
                .map_or("???".to_string(), |link| link.clone()),
            self.mtu,
        )
    }
}

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
