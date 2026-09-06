use tls_parser::TlsExtensionType;

/// Server Name Indication (IANA `server_name`)
pub const TLS_EXT_SERVER_NAME: u16 = TlsExtensionType::ServerName.0;
/// Application-Layer Protocol Negotiation (IANA `application_layer_protocol_negotiation`)
pub const TLS_EXT_ALPN: u16 = TlsExtensionType::ApplicationLayerProtocolNegotiation.0;
/// Padding extension (RFC 7685): covariant with ClientHello size
pub const TLS_EXT_PADDING: u16 = TlsExtensionType::Padding.0;
/// TLS Session Ticket extension (RFC 5077 / 8446)
pub const TLS_EXT_SESSION_TICKET: u16 = TlsExtensionType::SessionTicketTLS.0;
/// Pre-Shared Key extension (RFC 8446): resumption
pub const TLS_EXT_PRE_SHARED_KEY: u16 = TlsExtensionType::PreSharedKey.0;
/// early_data (RFC 8446): 0-RTT, travels with PSK
pub const TLS_EXT_EARLY_DATA: u16 = TlsExtensionType::EarlyData.0;
/// cookie (RFC 8446): second Hello of a HelloRetryRequest only. `JA4_s1`
/// candidate, not on [`S1_SESSION_EXTENSIONS`]
pub const TLS_EXT_COOKIE: u16 = TlsExtensionType::Cookie.0;
/// psk_key_exchange_modes (RFC 8446): mandatory when offering a PSK. `JA4_s1`
/// candidate, not on [`S1_SESSION_EXTENSIONS`]
pub const TLS_EXT_PSK_KEY_EXCHANGE_MODES: u16 = TlsExtensionType::PskExchangeModes.0;

/// Extension types dropped by `JA4_s1` (`feature = "stable-v1"`).
///
/// `padding` (`0015`), `session_ticket` (`0023`), `pre_shared_key` (`0029`) and
/// `early_data` (`002a`). Every other extension type, listed by IANA or not, is
/// hashed exactly as official JA4 hashes it: s1 removes session variance, not
/// signal.
///
/// Must stay sorted: lookup is a binary search.
///
/// Rationale, sources and curation rule:
/// <https://github.com/biandratti/huginn-net/blob/master/huginn-net-tls/JA4S1.md>
///
/// Not part of the FoxIO JA4 spec; `JA4_s1` is huginn-only.
#[cfg(feature = "stable-v1")]
#[cfg_attr(docsrs, doc(cfg(feature = "stable-v1")))]
pub const S1_SESSION_EXTENSIONS: &[u16] = &[
    TLS_EXT_PADDING,
    TLS_EXT_SESSION_TICKET,
    TLS_EXT_PRE_SHARED_KEY,
    TLS_EXT_EARLY_DATA,
];
