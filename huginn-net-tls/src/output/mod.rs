use crate::fingerprint::ObservableTlsClient;
use std::fmt;
use std::fmt::Formatter;

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
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
#[derive(Debug)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct TlsClientOutput {
    /// The source IP address and port of the client sending the ClientHello.
    pub source: IpPort,
    /// The destination IP address and port of the server receiving the ClientHello.
    pub destination: IpPort,
    /// The raw TLS signature extracted from the ClientHello packet.
    #[cfg_attr(feature = "json", serde(serialize_with = "serialize_tls_client"))]
    pub sig: ObservableTlsClient,
}

#[cfg(feature = "json")]
fn serialize_tls_client<S: serde::Serializer>(
    val: &ObservableTlsClient,
    s: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;
    let mut map = s.serialize_map(None)?;
    map.serialize_entry("sni", &val.sni)?;
    map.serialize_entry("version", &val.version.to_string())?;
    map.serialize_entry("alpn", &val.alpn)?;
    map.serialize_entry("ja4", val.ja4.full.value())?;
    map.serialize_entry("ja4_r", val.ja4.raw.value())?;
    map.serialize_entry("ja4_o", val.ja4_original.full.value())?;
    map.serialize_entry("ja4_or", val.ja4_original.raw.value())?;
    #[cfg(feature = "stable-v1")]
    map.serialize_entry("ja4_s1", val.ja4_stable_v1.full.value())?;
    #[cfg(feature = "stable-v1")]
    map.serialize_entry("ja4_s1r", val.ja4_stable_v1.raw.value())?;
    map.end()
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
        )?;
        #[cfg(feature = "stable-v1")]
        write!(
            f,
            "JA4_s1:  {}\n\
              JA4_s1r: {}\n",
            self.sig.ja4_stable_v1.full.value(),
            self.sig.ja4_stable_v1.raw.value(),
        )?;
        Ok(())
    }
}
