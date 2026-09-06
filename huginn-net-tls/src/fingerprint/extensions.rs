use tls_parser::TlsExtensionType;

/// Server Name Indication (IANA `server_name`)
pub const TLS_EXT_SERVER_NAME: u16 = TlsExtensionType::ServerName.0;
/// Application-Layer Protocol Negotiation (IANA `application_layer_protocol_negotiation`)
pub const TLS_EXT_ALPN: u16 = TlsExtensionType::ApplicationLayerProtocolNegotiation.0;
/// Padding extension (RFC 7685): covariant with ClientHello size
pub const TLS_EXT_PADDING: u16 = TlsExtensionType::Padding.0;
/// cached_info (RFC 7924): session / resumption
pub const TLS_EXT_CACHED_INFO: u16 = TlsExtensionType::CachedInfo.0;
/// ticket_pinning (RFC 8672): session / resumption. Not in `tls-parser` 0.12.
pub const TLS_EXT_TICKET_PINNING: u16 = 0x0020;
/// TLS Session Ticket extension (RFC 5077 / 8446): session / resumption
pub const TLS_EXT_SESSION_TICKET: u16 = TlsExtensionType::SessionTicketTLS.0;
/// Pre-Shared Key extension (RFC 8446): session / resumption
pub const TLS_EXT_PRE_SHARED_KEY: u16 = TlsExtensionType::PreSharedKey.0;
/// early_data (RFC 8446): 0-RTT, travels with PSK
pub const TLS_EXT_EARLY_DATA: u16 = TlsExtensionType::EarlyData.0;
/// cookie (RFC 8446): HelloRetryRequest only
pub const TLS_EXT_COOKIE: u16 = TlsExtensionType::Cookie.0;
/// psk_key_exchange_modes (RFC 8446): coupled to PSK by some stacks
pub const TLS_EXT_PSK_KEY_EXCHANGE_MODES: u16 = TlsExtensionType::PskExchangeModes.0;
/// ticket_request (RFC 9149): session / resumption. Not in `tls-parser` 0.12.
pub const TLS_EXT_TICKET_REQUEST: u16 = 0x003a;

/// Session / resumption extension types dropped by `JA4_s1`
/// (`feature = "stable-v1"`).
///
/// Sorted. Every other extension type, listed by IANA or not, is hashed exactly
/// as official JA4 hashes it: s1 removes session variance, not signal.
///
/// Membership follows RFC semantics rather than observation, so an extension
/// stays out of s1 even when a given capture never flips it. `0x002d`
/// `psk_key_exchange_modes` is the one judgement call: some stacks send it only
/// when offering a PSK, which would flip s1 between fresh and resumed
/// handshakes.
///
/// Adding an ID is a breaking s1 bump.
///
/// Rationale and curation rule:
/// <https://github.com/biandratti/huginn-net/blob/master/huginn-net-tls/JA4S1.md>
///
/// Not part of the FoxIO JA4 spec; `JA4_s1` is huginn-only.
#[cfg(feature = "stable-v1")]
#[cfg_attr(docsrs, doc(cfg(feature = "stable-v1")))]
pub const S1_SESSION_EXTENSIONS: &[u16] = &[
    TLS_EXT_PADDING,
    TLS_EXT_CACHED_INFO,
    TLS_EXT_TICKET_PINNING,
    TLS_EXT_SESSION_TICKET,
    TLS_EXT_PRE_SHARED_KEY,
    TLS_EXT_EARLY_DATA,
    TLS_EXT_COOKIE,
    TLS_EXT_PSK_KEY_EXCHANGE_MODES,
    TLS_EXT_TICKET_REQUEST,
];
