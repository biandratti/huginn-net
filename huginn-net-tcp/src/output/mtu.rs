use super::common::{IpPort, MatchQuality};
use std::fmt;
use std::fmt::Formatter;

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