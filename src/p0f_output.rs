use crate::db::Label;
use crate::packet::IpPort;
use crate::tcp::{Signature, Ttl};
use std::fmt;

pub struct P0fOutput {
    pub syn: Option<SynTCPOutput>,
    pub syn_ack: Option<SynAckTCPOutput>,
    pub mtu: Option<MTUOutput>,
    pub uptime: Option<UptimeOutput>,
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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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
            self.destination.ip,
            self.destination.port,
            self.source.ip,
            self.source.port,
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

pub struct MTUOutput {
    pub source: IpPort,
    pub destination: IpPort,
    pub link: String,
    pub mtu: u16,
}

impl fmt::Display for MTUOutput {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            ".-[ {}/{} -> {}/{} (mtu) ]-\n\
            |\n\
            | client   = {}\n\
            | link     = {}\n\
            | raw_mtu  = {}\n\
            `----\n",
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
            self.source.ip,
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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            ".-[ {}/{} -> {}/{} (uptime) ]-\n\
            |\n\
            | client   = {}\n\
            | uptime   = {} days, {} hrs, {} min (modulo {} days)\n\
            | raw_freq = {} Hz\n\
            `----\n",
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
            self.source.ip,
            self.days,
            self.hours,
            self.min,
            self.up_mod_days,
            self.freq,
        )
    }
}
