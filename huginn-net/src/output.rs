use huginn_net_http::output::{HttpRequestOutput, HttpResponseOutput};
use huginn_net_tcp::output::{MTUOutput, SynAckTCPOutput, SynTCPOutput, UptimeOutput};
use huginn_net_tls::output::TlsClientOutput;

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

    /// Information about the client system uptime.
    pub client_uptime: Option<UptimeOutput>,

    /// Information about the server system uptime.
    pub server_uptime: Option<UptimeOutput>,

    /// Information derived from HTTP request headers.
    pub http_request: Option<HttpRequestOutput>,

    /// Information derived from HTTP response headers.
    pub http_response: Option<HttpResponseOutput>,

    /// Information derived from TLS ClientHello analysis using JA4 fingerprinting.
    /// JA4 methodology by FoxIO, LLC - implementation from scratch for Huginn Net.
    pub tls_client: Option<TlsClientOutput>,
}
