use crate::ObservableTlsClient;
use std::fmt;
use std::fmt::Formatter;

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

/// Holds information derived from analyzing TLS ClientHello packets.
///
/// This structure contains details about the TLS client based on its ClientHello packet,
/// including the JA4 Payload and extracted TLS parameters.
pub struct TlsClientOutput {
    /// The source IP address and port of the client sending the ClientHello.
    pub source: IpPort,
    /// The destination IP address and port of the server receiving the ClientHello.
    pub destination: IpPort,
    /// The raw TLS signature extracted from the ClientHello packet.
    pub sig: ObservableTlsClient,
}

impl fmt::Display for TlsClientOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[TLS Client] {}:{} → {}:{}\n\
              SNI:     {}\n\
              Version: TLS {}\n\
              JA4:     {}\n\
              JA4_r:   {}\n\
              JA4_o:   {}\n\
              JA4_or:  {}\n",
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
            self.sig.sni.as_deref().unwrap_or("none"),
            self.sig.version,
            self.sig.ja4.full.value(),
            self.sig.ja4.raw.value(),
            self.sig.ja4_original.full.value(),
            self.sig.ja4_original.raw.value(),
        )
    }
}
