use crate::db::Label;
use crate::packet::ClientSource;
use crate::tcp::Signature;
use std::fmt;

pub struct P0fOutput {
    pub client: ClientSource,
    pub label: Option<Label>,
    pub sig: Signature,
}

//TODO: [WIP] Display output by type
impl fmt::Display for P0fOutput {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            ".-[ {} (syn) ]-\n\
            |\n\
            | os       = {}\n\
            | flavor   = {}\n\
            | raw_sig  = {}\n",
            format!("{}/{}", self.client.ip, self.client.port),
            self.label.as_ref().map_or("Unknown", |l| &l.name),
            self.label
                .as_ref()
                .map_or("Unknown", |l| &l.flavor.as_deref().unwrap_or("Unknown")),
            self.sig,
        )
    }
}
