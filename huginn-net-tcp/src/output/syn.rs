use super::common::{IpPort, OSQualityMatched};
use crate::observable::ObservableTcp;
use crate::tcp::Ttl;
use std::fmt;
use std::fmt::Formatter;

/// Holds information derived from analyzing a TCP SYN packet (client initiation).
#[derive(Debug)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct SynTCPOutput {
    /// The source IP address and port of the client sending the SYN.
    pub source: IpPort,
    /// The destination IP address and port of the server receiving the SYN.
    pub destination: IpPort,
    /// The operative system with the highest quality that matches the SYN packet.
    pub os_matched: OSQualityMatched,
    /// The raw TCP signature extracted from the SYN packet.
    #[cfg_attr(feature = "json", serde(serialize_with = "super::serialize_display"))]
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
