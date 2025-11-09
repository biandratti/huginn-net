use huginn_net_http::output::{HttpRequestOutput, HttpResponseOutput};
use huginn_net_tcp::output::{MTUOutput, SynAckTCPOutput, SynTCPOutput, UptimeOutput};
use huginn_net_tls::output::TlsClientOutput;

/// Represents the output from the Huginn Net analyzer.
///
/// This struct contains various optional outputs that can be derived
/// from analyzing TCP, HTTP, and TLS packets.
pub struct FingerprintResult {
    /// Information derived from TCP SYN packets.
    pub tcp_syn: Option<SynTCPOutput>,

    /// Information derived from TCP SYN-ACK packets.
    pub tcp_syn_ack: Option<SynAckTCPOutput>,

    /// Information about the TCP Maximum Transmission Unit (MTU).
    pub tcp_mtu: Option<MTUOutput>,

    /// Information about the TCP client system uptime.
    pub tcp_client_uptime: Option<UptimeOutput>,

    /// Information about the TCP server system uptime.
    pub tcp_server_uptime: Option<UptimeOutput>,

    /// Information derived from HTTP request headers.
    pub http_request: Option<HttpRequestOutput>,

    /// Information derived from HTTP response headers.
    pub http_response: Option<HttpResponseOutput>,

    /// Information derived from TLS ClientHello analysis using JA4 fingerprinting.
    /// JA4 methodology by FoxIO, LLC - implementation from scratch for Huginn Net.
    pub tls_client: Option<TlsClientOutput>,
}
