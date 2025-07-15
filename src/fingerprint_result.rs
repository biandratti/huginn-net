use crate::db::{Label, Type};
use crate::http::HttpDiagnosis;
use crate::observable_signals::{ObservableHttpRequest, ObservableHttpResponse};
use crate::observable_signals::{ObservableTcp, ObservableTlsClient};
use crate::process::IpPort;
use crate::tcp::Ttl;
use std::fmt;
use std::fmt::Formatter;

const YELLOW: &str = "\x1b[33m";
const RESET: &str = "\x1b[0m";
const LIGHT_BLUE: &str = "\x1b[94m";

fn colored(text: &str, color: &str) -> String {
    format!("{}{}{}", color, text, RESET)
}

fn write_key_values(f: &mut Formatter<'_>, pairs: &[(&str, String)]) -> fmt::Result {
    let max_len = pairs.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    for (key, value) in pairs {
        let padding = max_len - key.len();
        writeln!(
            f,
            "| {}{} = {}",
            colored(key, LIGHT_BLUE),
            " ".repeat(padding),
            value
        )?;
    }
    Ok(())
}

/// Represents the output from the Huginn Net analyzer.
///
/// This struct contains various optional outputs that can be derived
/// from analyzing TCP, HTTP, and TLS packets.
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

    /// Information derived from TLS ClientHello analysis using JA4 fingerprinting.
    /// JA4 methodology by FoxIO, LLC - implementation from scratch for Huginn Net.
    pub tls_client: Option<TlsClientOutput>,
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
        writeln!(
            f,
            "{}.-[ {}/{} -> {}/{} (syn) ]-{}",
            YELLOW,
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
            RESET
        )?;
        writeln!(f, "|")?;

        let pairs = [
            ("client", format!("{}/{}", self.source.ip, self.source.port)),
            (
                "os",
                self.os_matched.as_ref().map_or("???".to_string(), |l| {
                    format!(
                        "{}/{}/{}",
                        l.os.name,
                        l.os.family.as_deref().unwrap_or("???"),
                        l.os.variant.as_deref().unwrap_or("??")
                    )
                }),
            ),
            (
                "dist",
                match self.sig.ittl {
                    Ttl::Distance(_, d) => d,
                    Ttl::Bad(v) | Ttl::Value(v) | Ttl::Guess(v) => v,
                }
                .to_string(),
            ),
            (
                "params",
                self.os_matched
                    .as_ref()
                    .map_or("none".to_string(), |l| l.os.kind.to_string()),
            ),
            ("raw_sig", self.sig.to_string()),
        ];

        write_key_values(f, &pairs)?;
        writeln!(f, "`----")
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
        writeln!(
            f,
            "{}.-[ {}/{} -> {}/{} (syn+ack) ]-{}",
            YELLOW,
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
            RESET
        )?;
        writeln!(f, "|")?;

        let pairs = [
            (
                "server",
                format!("{}/{}", self.destination.ip, self.destination.port),
            ),
            (
                "os",
                self.os_matched.as_ref().map_or("???".to_string(), |l| {
                    format!(
                        "{}/{}/{}",
                        l.os.name,
                        l.os.family.as_deref().unwrap_or("???"),
                        l.os.variant.as_deref().unwrap_or("??")
                    )
                }),
            ),
            (
                "dist",
                match self.sig.ittl {
                    Ttl::Distance(_, d) => d,
                    Ttl::Bad(v) | Ttl::Value(v) | Ttl::Guess(v) => v,
                }
                .to_string(),
            ),
            (
                "params",
                self.os_matched
                    .as_ref()
                    .map_or("none".to_string(), |l| l.os.kind.to_string()),
            ),
            ("raw_sig", self.sig.to_string()),
        ];

        write_key_values(f, &pairs)?;
        writeln!(f, "`----")
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
        writeln!(
            f,
            "{}.-[ {}/{} -> {}/{} (mtu) ]-{}",
            YELLOW,
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
            RESET
        )?;
        writeln!(f, "|")?;

        let pairs = [
            (
                "server",
                format!("{}/{}", self.destination.ip, self.destination.port),
            ),
            ("link", self.link.clone()),
            ("raw_mtu", self.mtu.to_string()),
        ];

        write_key_values(f, &pairs)?;
        writeln!(f, "`----")
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
        writeln!(
            f,
            "{}.-[ {}/{} -> {}/{} (uptime) ]-{}",
            YELLOW,
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
            RESET
        )?;
        writeln!(f, "|")?;

        let pairs = [
            (
                "client",
                format!("{}/{}", self.destination.ip, self.destination.port),
            ),
            (
                "uptime",
                format!(
                    "{} days, {} hrs, {} min (modulo {} days)",
                    self.days, self.hours, self.min, self.up_mod_days
                ),
            ),
            ("raw_freq", format!("{:.2} Hz", self.freq)),
        ];

        write_key_values(f, &pairs)?;
        writeln!(f, "`----")
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
        writeln!(
            f,
            "{}.-[ {}/{} -> {}/{} (http request) ]-{}",
            YELLOW,
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
            RESET
        )?;
        writeln!(f, "|")?;

        let pairs = [
            ("client", format!("{}/{}", self.source.ip, self.source.port)),
            (
                "app",
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
            ),
            ("lang", self.lang.as_deref().unwrap_or("???").to_string()),
            ("params", self.diagnosis.to_string()),
            ("raw_sig", self.sig.to_string()),
        ];

        write_key_values(f, &pairs)?;
        writeln!(f, "`----")
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
        writeln!(
            f,
            "{}.-[ {}/{} -> {}/{} (http response) ]-{}",
            YELLOW,
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
            RESET
        )?;
        writeln!(f, "|")?;

        let pairs = [
            (
                "server",
                format!("{}/{}", self.destination.ip, self.destination.port),
            ),
            (
                "app",
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
            ),
            ("params", self.diagnosis.to_string()),
            ("raw_sig", self.sig.to_string()),
        ];

        write_key_values(f, &pairs)?;
        writeln!(f, "`----")
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
        writeln!(
            f,
            "{}.-[ {}/{} -> {}/{} (tls client) ]-{}",
            YELLOW,
            self.source.ip,
            self.source.port,
            self.destination.ip,
            self.destination.port,
            RESET
        )?;
        writeln!(f, "|")?;

        let pairs = [
            ("client", format!("{}/{}", self.source.ip, self.source.port)),
            ("ja4", self.sig.ja4.full.value().to_string()),
            ("ja4_r", self.sig.ja4.raw.value().to_string()),
            ("ja4_o", self.sig.ja4_original.full.value().to_string()),
            ("ja4_or", self.sig.ja4_original.raw.value().to_string()),
            ("sni", self.sig.sni.as_deref().unwrap_or("none").to_string()),
            ("version", self.sig.version.to_string()),
        ];

        write_key_values(f, &pairs)?;
        writeln!(f, "`----")
    }
}
