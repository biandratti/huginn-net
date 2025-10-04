use crate::observable::ObservableTcp;
use huginn_net_db::tcp::Ttl;
use huginn_net_db::{Label, MatchQualityType, Type};
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

    /// Information about the system uptime.
    pub uptime: Option<UptimeOutput>,
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

/// Represents an operative system.
///
/// This struct contains the name, family, variant, and kind of operative system.
/// Examples:
/// - name: "Linux", family: "unix", variant: "2.2.x-3.x", kind: Type::Specified
/// - name: "Windows", family: "win", variant: "NT kernel 6.x", kind: Type::Specified
/// - name: "iOS", family: "unix", variant: "iPhone or iPad", kind: Type::Specified
#[derive(Debug)]
pub struct OperativeSystem {
    pub name: String,
    pub family: Option<String>,
    pub variant: Option<String>,
    pub kind: Type,
}

impl From<&Label> for OperativeSystem {
    fn from(label: &Label) -> Self {
        OperativeSystem {
            name: label.name.clone(),
            family: label.class.clone(),
            variant: label.flavor.clone(),
            kind: label.ty.clone(),
        }
    }
}

/// The operative system with the highest quality that matches the packet. Quality is a value between 0.0 and 1.0. 1.0 is a perfect match.
#[derive(Debug)]
pub struct OSQualityMatched {
    pub os: Option<OperativeSystem>,
    pub quality: MatchQualityType,
}

/// Holds information derived from analyzing a TCP SYN packet (client initiation).
///
/// This structure contains details about the client system based on its SYN packet,
/// including the identified OS/application label and the raw TCP signature.
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
            ".-[ {}/{} -> {}/{} (syn) ]-\n\
            |\n\
            | client   = {}/{}\n\
            | os       = {}\n\
            | dist     = {}\n\
            | params   = {}\n\
            | raw_sig  = {}\n\
            `----\n",
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
            self.source.ip,
            self.source.port,
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
///
/// This structure contains details about the server system based on its SYN+ACK packet,
/// including the identified OS/application label and the raw TCP signature.
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
            ".-[ {}/{} -> {}/{} (syn+ack) ]-\n\
            |\n\
            | server   = {}/{}\n\
            | os       = {}\n\
            | dist     = {}\n\
            | params   = {}\n\
            | raw_sig  = {}\n\
            `----\n",
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
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
    pub quality: MatchQualityType,
}

/// Holds information about the estimated Maximum Transmission Unit (MTU) of a link.
///
/// This structure contains the source and destination addresses, an estimation
/// of the link type based on common MTU values, and the calculated raw MTU value.
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
            ".-[ {}/{} -> {}/{} (mtu) ]-\n\
            |\n\
            | server   = {}/{}\n\
            | link     = {}\n\
            | raw_mtu  = {}\n\
            `----\n",
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
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

/// Holds uptime information derived from TCP timestamp analysis.
///
/// This structure contains the estimated uptime components (days, hours, minutes),
/// the timestamp clock's wraparound period (`up_mod_days`), and the calculated
/// clock frequency (`freq`). Note that the days/hours/minutes calculation based
/// on the timestamp value might be approximate.
#[derive(Debug)]
pub struct UptimeOutput {
    /// The source IP address and port of the connection.
    pub source: IpPort,
    /// The destination IP address and port of the connection.
    pub destination: IpPort,
    /// Estimated uptime in days, derived from the TCP timestamp value. Potentially approximate.
    pub days: u32,
    /// Estimated uptime component in hours. Potentially approximate.
    pub hours: u32,
    /// Estimated uptime component in minutes. Potentially approximate.
    pub min: u32,
    /// The calculated period in days after which the timestamp counter wraps around (2^32 ticks).
    pub up_mod_days: u32,
    /// The calculated frequency of the remote system's timestamp clock in Hertz (Hz).
    pub freq: f64,
}

impl fmt::Display for UptimeOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            ".-[ {}/{} -> {}/{} (uptime) ]-\n\
            |\n\
            | client   = {}/{}\n\
            | uptime   = {} days, {} hrs, {} min (modulo {} days)\n\
            | raw_freq = {:.2} Hz\n\
            `----\n",
            self.destination.ip,
            self.destination.port,
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
