#[cfg(any(feature = "http-akamai-cleartext", feature = "http-akamai-keylog"))]
use huginn_net_http::output::AkamaiOutput;
#[cfg(feature = "http-p0f-request")]
use huginn_net_http::output::HttpRequestOutput;
#[cfg(feature = "http-p0f-response")]
use huginn_net_http::output::HttpResponseOutput;
#[cfg(feature = "tcp-mtu")]
use huginn_net_tcp::output::MTUOutput;
#[cfg(feature = "tcp-syn-ack")]
use huginn_net_tcp::output::SynAckTCPOutput;
#[cfg(feature = "tcp-syn")]
use huginn_net_tcp::output::SynTCPOutput;
#[cfg(feature = "tcp-uptime")]
use huginn_net_tcp::output::UptimeOutput;
use huginn_net_tls::output::TlsClientOutput;

/// Represents the output from the Huginn Net analyzer.
///
/// This struct contains various optional outputs that can be derived
/// from analyzing TCP, HTTP, and TLS packets.
#[derive(Debug)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct FingerprintResult {
    /// Information derived from TCP SYN packets.
    ///
    /// Present only when the `tcp-syn` feature is enabled.
    #[cfg(feature = "tcp-syn")]
    pub tcp_syn: Option<SynTCPOutput>,

    /// Information derived from TCP SYN-ACK packets.
    ///
    /// Present only when the `tcp-syn-ack` feature is enabled.
    #[cfg(feature = "tcp-syn-ack")]
    pub tcp_syn_ack: Option<SynAckTCPOutput>,

    /// Information about the TCP Maximum Transmission Unit (MTU).
    ///
    /// Present only when the `tcp-mtu` feature is enabled.
    #[cfg(feature = "tcp-mtu")]
    pub tcp_mtu: Option<MTUOutput>,

    /// Information about the TCP client system uptime.
    ///
    /// Present only when the `tcp-uptime` feature is enabled.
    #[cfg(feature = "tcp-uptime")]
    pub tcp_client_uptime: Option<UptimeOutput>,

    /// Information about the TCP server system uptime.
    ///
    /// Present only when the `tcp-uptime` feature is enabled.
    #[cfg(feature = "tcp-uptime")]
    pub tcp_server_uptime: Option<UptimeOutput>,

    /// Information derived from HTTP request headers.
    ///
    /// Present only when the `http-p0f-request` feature is enabled.
    #[cfg(feature = "http-p0f-request")]
    pub http_request: Option<HttpRequestOutput>,

    /// Information derived from HTTP response headers.
    ///
    /// Present only when the `http-p0f-response` feature is enabled.
    #[cfg(feature = "http-p0f-response")]
    pub http_response: Option<HttpResponseOutput>,

    /// Akamai HTTP/2 client fingerprint of the connection, emitted at most once per connection.
    ///
    /// Present only when the `http-akamai-cleartext` or `http-akamai-keylog` feature is enabled.
    #[cfg(any(feature = "http-akamai-cleartext", feature = "http-akamai-keylog"))]
    pub http_akamai: Option<AkamaiOutput>,

    /// Information derived from TLS ClientHello analysis using JA4 fingerprinting.
    /// JA4 methodology by FoxIO, LLC - implementation from scratch for Huginn Net.
    pub tls_client: Option<TlsClientOutput>,
}

impl FingerprintResult {
    /// A result with every field empty.
    #[cfg(feature = "http-akamai-keylog")]
    pub(crate) fn empty() -> Self {
        Self {
            #[cfg(feature = "tcp-syn")]
            tcp_syn: None,
            #[cfg(feature = "tcp-syn-ack")]
            tcp_syn_ack: None,
            #[cfg(feature = "tcp-mtu")]
            tcp_mtu: None,
            #[cfg(feature = "tcp-uptime")]
            tcp_client_uptime: None,
            #[cfg(feature = "tcp-uptime")]
            tcp_server_uptime: None,
            #[cfg(feature = "http-p0f-request")]
            http_request: None,
            #[cfg(feature = "http-p0f-response")]
            http_response: None,
            http_akamai: None,
            tls_client: None,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        #[cfg(feature = "tcp-syn")]
        if self.tcp_syn.is_some() {
            return false;
        }
        #[cfg(feature = "tcp-syn-ack")]
        if self.tcp_syn_ack.is_some() {
            return false;
        }
        #[cfg(feature = "tcp-mtu")]
        if self.tcp_mtu.is_some() {
            return false;
        }
        #[cfg(feature = "tcp-uptime")]
        if self.tcp_client_uptime.is_some() {
            return false;
        }
        #[cfg(feature = "tcp-uptime")]
        if self.tcp_server_uptime.is_some() {
            return false;
        }
        #[cfg(feature = "http-p0f-request")]
        if self.http_request.is_some() {
            return false;
        }
        #[cfg(feature = "http-p0f-response")]
        if self.http_response.is_some() {
            return false;
        }
        #[cfg(any(feature = "http-akamai-cleartext", feature = "http-akamai-keylog"))]
        if self.http_akamai.is_some() {
            return false;
        }
        if self.tls_client.is_some() {
            return false;
        }
        true
    }
}
