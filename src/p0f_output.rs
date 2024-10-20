use crate::db::Label;
use crate::packet::IpPort;
use crate::tcp::{Signature, Ttl};
use std::fmt;

pub struct P0fOutput {
    pub client: IpPort,
    pub server: IpPort,
    pub is_client: bool,
    pub label: Option<Label>,
    pub sig: Signature,
}

//TODO: [WIP] Display output by type
impl fmt::Display for P0fOutput {
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
