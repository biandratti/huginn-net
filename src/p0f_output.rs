use crate::db::Label;
use crate::packet::IpPort;
use crate::tcp::{Signature, Ttl};
use std::fmt;

pub struct P0fOutput {
    pub syn_ack: Option<SynAckTCPOutput>,
    pub mtu: Option<MTUOutput>,
}

pub struct SynAckTCPOutput {
    pub client: IpPort,
    pub server: IpPort, //TODO: Option<IpPort>,
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
            self.client.ip,
            self.client.port,
            self.server.ip,
            self.server.port,
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
    pub client: IpPort,
    pub server: IpPort,
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
            self.client.ip,
            self.client.port,
            self.server.ip,
            self.server.port,
            self.client.ip,
            self.link,
            self.mtu,
        )
    }
}
