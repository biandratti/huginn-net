use crate::db::Label;
use crate::packet::IpPort;
use crate::tcp::{Signature, Ttl};
use std::fmt;

pub struct P0fOutput {
    pub syn_ack: Option<SynAckTCPOutput>,
    pub mtu: Option<MTUOutput>,
    pub uptime: Option<UptimeOutput>,
}

pub struct SynAckTCPOutput {
    pub source: IpPort,
    pub destination: IpPort, //TODO: Option<IpPort>,
    pub is_client: bool,
    pub label: Option<Label>,
    pub sig: Signature,
}

impl fmt::Display for SynAckTCPOutput {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            ".-[ {}/{} -> {}/{} ({}) ]-\n\
            |\n\
            | {}   = {}/{}\n\
            | dist     = {}\n\
            | params   = {}\n\
            | raw_sig  = {}\n\
            `----\n",
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
            if self.is_client { "syn" } else { "syn+ack" },
            if self.is_client { "client" } else { "server" },
            self.label.as_ref().map_or("Unknown", |l| &l.name),
            self.label
                .as_ref()
                .map_or("Unknown", |l| l.flavor.as_deref().unwrap_or("Unknown")),
            match self.sig.ittl {
                Ttl::Distance(_, distance) => distance,
                _ => "Unknown".parse().unwrap(),
            },
            self.label
                .as_ref()
                .map_or("Unknown".to_string(), |l| l.ty.to_string()),
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
