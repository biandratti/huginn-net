use crate::db::{Label, Type};
use crate::http::HttpDiagnosis;
use crate::observable_signals::ObservableTcp;
#[cfg(feature = "tls")]
use crate::observable_signals::ObservableTlsClient;
use crate::observable_signals::{ObservableHttpRequest, ObservableHttpResponse};
use crate::process::IpPort;
use crate::tcp::Ttl;
use std::fmt;
use std::fmt::Formatter;

/// Represents the output from the passive TCP fingerprinting tool.
///
/// This struct contains various optional outputs that can be derived
/// from analyzing TCP packets, such as SYN, SYN-ACK, MTU, uptime, and protocol-specific data.
pub struct FingerprintResult {
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

    /// TLS protocol analysis results
    #[cfg(feature = "tls")]
    pub tls: TlsProtocol,
}

/// Container for TLS protocol analysis results
#[cfg(feature = "tls")]
#[derive(Debug, Default)]
pub struct TlsProtocol {
    /// Information derived from TLS ClientHello analysis. Based on FoxIO
    pub client: Option<TlsClientOutput>,
}

/// Represents an operative system.
///
/// This struct contains the name, family, variant, and kind of operative system.
/// Examples:
/// - name: "Linux", family: "unix", variant: "2.2.x-3.x", kind: Type::Specified
/// - name: "Windows", family: "win", variant: "NT kernel 6.x", kind: Type::Specified
/// - name: "iOS", family: "unix", variant: "iPhone or iPad", kind: Type::Specified
pub struct OperativeSystem {
    pub name: String,
    pub family: Option<String>,
    pub variant: Option<String>,
    pub kind: Type,
}

impl From<&Label> for OperativeSystem {
    fn from(label: &Label) -> Self {
        OperativeSystem {
            name: label.name.clone(),
            family: label.class.clone(),
            variant: label.flavor.clone(),
            kind: label.ty.clone(),
        }
    }
}

/// The operative system with the highest quality that matches the packet. Quality is a value between 0.0 and 1.0. 1.0 is a perfect match.
pub struct OSQualityMatched {
    pub os: OperativeSystem,
    pub quality: f32,
}

/// Holds information derived from analyzing a TCP SYN packet (client initiation).
///
/// This structure contains details about the client system based on its SYN packet,
/// including the identified OS/application label and the raw TCP signature.
pub struct SynTCPOutput {
    /// The source IP address and port of the client sending the SYN.
    pub source: IpPort,
    /// The destination IP address and port of the server receiving the SYN.
    pub destination: IpPort,
    /// The operative system with the highest quality that matches the SYN packet.
    pub os_matched: Option<OSQualityMatched>,
    /// The raw TCP signature extracted from the SYN packet.
    pub sig: ObservableTcp,
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
            self.os_matched.as_ref().map_or("???".to_string(), |l| {
                format!(
                    "{}/{}/{}",
                    l.os.name,
                    l.os.family.as_deref().unwrap_or("???"),
                    l.os.variant.as_deref().unwrap_or("??")
                )
            }),
            match self.sig.ittl {
                Ttl::Distance(_, distance) => distance,
                Ttl::Bad(value) => value,
                Ttl::Value(value) => value,
                Ttl::Guess(value) => value,
            },
            self.os_matched
                .as_ref()
                .map_or("none".to_string(), |l| l.os.kind.to_string()),
            self.sig,
        )
    }
}

/// Holds information derived from analyzing a TCP SYN+ACK packet (server response).
///
/// This structure contains details about the server system based on its SYN+ACK packet,
/// including the identified OS/application label and the raw TCP signature.
pub struct SynAckTCPOutput {
    /// The source IP address and port of the server sending the SYN+ACK.
    pub source: IpPort,
    /// The destination IP address and port of the client receiving the SYN+ACK.
    pub destination: IpPort,
    /// The operative system with the highest quality that matches the SYN+ACK packet.
    pub os_matched: Option<OSQualityMatched>,
    /// The raw TCP signature extracted from the SYN+ACK packet.
    pub sig: ObservableTcp,
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
            self.os_matched.as_ref().map_or("???".to_string(), |l| {
                format!(
                    "{}/{}/{}",
                    l.os.name,
                    l.os.family.as_deref().unwrap_or("???"),
                    l.os.variant.as_deref().unwrap_or("??")
                )
            }),
            match self.sig.ittl {
                Ttl::Distance(_, distance) => distance,
                Ttl::Bad(value) => value,
                Ttl::Value(value) => value,
                Ttl::Guess(value) => value,
            },
            self.os_matched
                .as_ref()
                .map_or("none".to_string(), |l| l.os.kind.to_string()),
            self.sig,
        )
    }
}

/// Holds information about the estimated Maximum Transmission Unit (MTU) of a link.
///
/// This structure contains the source and destination addresses, an estimation
/// of the link type based on common MTU values, and the calculated raw MTU value.
pub struct MTUOutput {
    /// The source IP address and port (usually the client).
    pub source: IpPort,
    /// The destination IP address and port (usually the server).
    pub destination: IpPort,
    /// An estimated link type (e.g., "Ethernet", "PPPoE") based on the calculated MTU.
    pub link: String,
    /// The calculated Maximum Transmission Unit (MTU) value in bytes.
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

/// Holds uptime information derived from TCP timestamp analysis.
///
/// This structure contains the estimated uptime components (days, hours, minutes),
/// the timestamp clock's wraparound period (`up_mod_days`), and the calculated
/// clock frequency (`freq`). Note that the days/hours/minutes calculation based
/// on the timestamp value might be approximate.
pub struct UptimeOutput {
    /// The source IP address and port of the connection.
    pub source: IpPort,
    /// The destination IP address and port of the connection.
    pub destination: IpPort,
    /// Estimated uptime in days, derived from the TCP timestamp value. Potentially approximate.
    pub days: u32,
    /// Estimated uptime component in hours. Potentially approximate.
    pub hours: u32,
    /// Estimated uptime component in minutes. Potentially approximate.
    pub min: u32,
    /// The calculated period in days after which the timestamp counter wraps around (2^32 ticks).
    pub up_mod_days: u32,
    /// The calculated frequency of the remote system's timestamp clock in Hertz (Hz).
    pub freq: f64,
}

impl fmt::Display for UptimeOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            ".-[ {}/{} -> {}/{} (uptime) ]-\n\
            |\n\
            | client   = {}/{}\n\
            | uptime   = {} days, {} hrs, {} min (modulo {} days)\n\
            | raw_freq = {:.2} Hz\n\
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

pub struct BrowserQualityMatched {
    pub browser: Browser,
    pub quality: f32,
}

/// Represents a browser.
///
/// This struct contains the name, family, variant, and kind of browser.
/// Examples:
/// - name: "", family: "chrome", variant: "11.x to 26.x", kind: Type::Specified
/// - name: "", family: "firefox", variant: "3.x", kind: Type::Specified
pub struct Browser {
    pub name: String,
    pub family: Option<String>,
    pub variant: Option<String>,
    pub kind: Type,
}

impl From<&Label> for Browser {
    fn from(label: &Label) -> Self {
        Browser {
            name: label.name.clone(),
            family: label.class.clone(),
            variant: label.flavor.clone(),
            kind: label.ty.clone(),
        }
    }
}

/// Holds information derived from analyzing HTTP request headers.
///
/// This structure contains details about the client, the detected application
/// (if any), the preferred language, diagnostic parameters related to HTTP behavior,
/// and the raw HTTP signature.
pub struct HttpRequestOutput {
    /// The source IP address and port of the client making the request.
    pub source: IpPort,
    /// The destination IP address and port of the server receiving the request.
    pub destination: IpPort,
    /// The preferred language indicated in the `Accept-Language` header, if present.
    pub lang: Option<String>,
    /// Diagnostic information about potential HTTP specification violations or common practices.
    pub diagnosis: HttpDiagnosis,
    /// The browser with the highest quality that matches the HTTP request.
    pub browser_matched: Option<BrowserQualityMatched>,
    /// The raw signature representing the HTTP headers and their order.
    pub sig: ObservableHttpRequest,
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
            self.browser_matched
                .as_ref()
                .map_or("???".to_string(), |l| {
                    format!(
                        "{}/{}/{}",
                        l.browser.name,
                        l.browser.family.as_deref().unwrap_or("???"),
                        l.browser.variant.as_deref().unwrap_or("???")
                    )
                }),
            self.lang.as_deref().unwrap_or("???"),
            self.diagnosis,
            self.sig,
        )
    }
}

pub struct WebServerQualityMatched {
    pub web_server: WebServer,
    pub quality: f32,
}

/// Represents a web server.
///
/// This struct contains the name, family, variant, and kind of browser.
/// Examples:
/// - name: "", family: "apache", variant: "2.x", kind: Type::Specified
/// - name: "", family: "nginx", variant: "1.x", kind: Type::Specified
pub struct WebServer {
    pub name: String,
    pub family: Option<String>,
    pub variant: Option<String>,
    pub kind: Type,
}

impl From<&Label> for WebServer {
    fn from(label: &Label) -> Self {
        WebServer {
            name: label.name.clone(),
            family: label.class.clone(),
            variant: label.flavor.clone(),
            kind: label.ty.clone(),
        }
    }
}

/// Holds information derived from analyzing HTTP response headers.
///
/// This structure contains details about the server, the detected application
/// (if any), diagnostic parameters related to HTTP behavior, and the raw HTTP signature.
pub struct HttpResponseOutput {
    /// The source IP address and port of the server sending the response.
    pub source: IpPort,
    /// The destination IP address and port of the client receiving the response.
    pub destination: IpPort,
    /// Diagnostic information about potential HTTP specification violations or common practices.
    pub diagnosis: HttpDiagnosis,
    /// The label identifying the likely server application (e.g., Apache, Nginx) and the quality.
    pub web_server_matched: Option<WebServerQualityMatched>,
    /// The raw signature representing the HTTP headers and their order.
    pub sig: ObservableHttpResponse,
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
            self.web_server_matched
                .as_ref()
                .map_or("???".to_string(), |l| {
                    format!(
                        "{}/{}/{}",
                        l.web_server.name,
                        l.web_server.family.as_deref().unwrap_or("???"),
                        l.web_server.variant.as_deref().unwrap_or("???")
                    )
                }),
            self.diagnosis,
            self.sig,
        )
    }
}

/// Holds information derived from analyzing TLS ClientHello packets.
///
/// This structure contains details about the TLS client based on its ClientHello packet,
/// including the JA4 Payload and extracted TLS parameters.
#[cfg(feature = "tls")]
#[derive(Debug)]
pub struct TlsClientOutput {
    /// The source IP address and port of the client sending the ClientHello.
    pub source: IpPort,
    /// The destination IP address and port of the server receiving the ClientHello.
    pub destination: IpPort,
    /// The raw TLS signature extracted from the ClientHello packet.
    pub sig: ObservableTlsClient,
}

#[cfg(feature = "tls")]
impl fmt::Display for TlsClientOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            ".-[ {}/{} -> {}/{} (tls) ]-\n\
            |\n\
            | client   = {}/{}\n\
            | ja4      = {}\n\
            | ja4_r    = {}\n\
            | ja4_o    = {}\n\
            | ja4_or   = {}\n\
            | sni      = {}\n\
            | version  = {}\n\
            `----\n",
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
            self.source.ip,
            self.source.port,
            self.sig.ja4.full.value(),
            self.sig.ja4.raw.value(),
            self.sig.ja4_original.full.value(),
            self.sig.ja4_original.raw.value(),
            self.sig.sni.as_deref().unwrap_or("none"),
            self.sig.version,
        )
    }
}
