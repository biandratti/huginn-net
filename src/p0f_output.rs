use crate::db::Label;
use crate::http;
use crate::http::HttpDiagnosis;
use crate::process::IpPort;
use crate::tcp::{Signature, Ttl};
use std::fmt;
use std::fmt::Formatter;

/// Represents the output from the passive TCP fingerprinting tool.
///
/// This struct contains various optional outputs that can be derived
/// from analyzing TCP packets, such as SYN, SYN-ACK, MTU, uptime, and HTTP data.
pub struct P0fOutput {
    /// Information derived from SYN packets.
    pub syn: Option<SynTCPOutput>,

    /// Information derived from SYN-ACK packets.
    pub syn_ack: Option<SynAckTCPOutput>,

    /// Information about the Maximum Transmission Unit (MTU).
    pub mtu: Option<MTUOutput>,

    /// Information about the system uptime.
    pub uptime: Option<UptimeOutput>,

    /// Information derived from HTTP request headers.
    pub http_request: Option<HttpRequestOutput>,

    /// Information derived from HTTP response headers.
    pub http_response: Option<HttpResponseOutput>,
}

pub struct SynTCPOutput {
    pub source: IpPort,
    pub destination: IpPort,
    pub label: Option<Label>,
    pub sig: Signature,
}

pub struct SynAckTCPOutput {
    pub source: IpPort,
    pub destination: IpPort,
    pub label: Option<Label>,
    pub sig: Signature,
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
            self.label.as_ref().map_or("???".to_string(), |l| {
                format!("{}/{}", l.name, l.flavor.as_deref().unwrap_or("???"))
            }),
            match self.sig.ittl {
                Ttl::Distance(_, distance) => distance,
                _ => "Unknown".parse().unwrap(),
            },
            self.label
                .as_ref()
                .map_or("none".to_string(), |l| l.ty.to_string()),
            self.sig,
        )
    }
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
            self.label.as_ref().map_or("???".to_string(), |l| {
                format!("{}/{}", l.name, l.flavor.as_deref().unwrap_or("???"))
            }),
            match self.sig.ittl {
                Ttl::Distance(_, distance) => distance,
                Ttl::Bad(value) => value,
                Ttl::Value(value) => value,
                Ttl::Guess(value) => value,
            },
            self.label
                .as_ref()
                .map_or("none".to_string(), |l| l.ty.to_string()),
            self.sig,
        )
    }
}

pub struct MTUOutput {
    pub source: IpPort,
    pub destination: IpPort,
    pub link: String,
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
            self.link,
            self.mtu,
        )
    }
}

pub struct UptimeOutput {
    pub source: IpPort,
    pub destination: IpPort,
    pub days: u32,
    pub hours: u32,
    pub min: u32,
    pub up_mod_days: u32,
    pub freq: u32,
}

impl fmt::Display for UptimeOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            ".-[ {}/{} -> {}/{} (uptime) ]-\n\
            |\n\
            | client   = {}/{}\n\
            | uptime   = {} days, {} hrs, {} min (modulo {} days)\n\
            | raw_freq = {} Hz\n\
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

pub struct HttpRequestOutput {
    pub source: IpPort,
    pub destination: IpPort,
    pub lang: Option<String>,
    pub diagnosis: HttpDiagnosis,
    pub label: Option<Label>,
    pub sig: http::Signature,
}

impl fmt::Display for HttpRequestOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            ".-[ {}/{} -> {}/{} (http request) ]-\n\
            |\n\
            | client   = {}/{}\n\
            | app      = {}\n\
            | lang     = {}\n\
            | params   = {}\n\
            | raw_sig  = {}\n\
            `----\n",
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
            self.source.ip,
            self.source.port,
            self.label
                .as_ref()
                .map_or("???".to_string(), |l| l.name.clone()),
            self.lang.as_deref().unwrap_or("???"),
            self.diagnosis,
            self.sig,
        )
    }
}

pub struct HttpResponseOutput {
    pub source: IpPort,
    pub destination: IpPort,
    pub diagnosis: HttpDiagnosis,
    pub label: Option<Label>,
    pub sig: http::Signature,
}

impl fmt::Display for HttpResponseOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            ".-[ {}/{} -> {}/{} (http response) ]-\n\
            |\n\
            | server   = {}/{}\n\
            | app      = {}\n\
            | params   = {}\n\
            | raw_sig  = {}\n\
            `----\n",
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
            self.destination.ip,
            self.destination.port,
            self.label
                .as_ref()
                .map_or("???".to_string(), |l| l.name.clone()),
            self.diagnosis,
            self.sig,
        )
    }
}
