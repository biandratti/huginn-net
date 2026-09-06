#[cfg(feature = "stable-v1")]
use std::borrow::Cow;

/// See <https://datatracker.ietf.org/doc/html/draft-davidben-tls-grease-01#page-5>
pub const TLS_GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// Server Name Indication (IANA `server_name`)
pub const TLS_EXT_SERVER_NAME: u16 = 0x0000;
/// Application-Layer Protocol Negotiation (IANA `application_layer_protocol_negotiation`)
pub const TLS_EXT_ALPN: u16 = 0x0010;
/// TLS Session Ticket extension (RFC 5077 / 8446): session / resumption
pub const TLS_EXT_SESSION_TICKET: u16 = 0x0023;
/// Pre-Shared Key extension (RFC 8446): session / resumption
pub const TLS_EXT_PRE_SHARED_KEY: u16 = 0x0029;
/// Padding extension (RFC 7685): covariant with ClientHello size
pub const TLS_EXT_PADDING: u16 = 0x0015;
/// early_data (RFC 8446): 0-RTT, travels with PSK
pub const TLS_EXT_EARLY_DATA: u16 = 0x002a;
/// cookie (RFC 8446): HelloRetryRequest only
pub const TLS_EXT_COOKIE: u16 = 0x002c;
/// psk_key_exchange_modes (RFC 8446): coupled to PSK by some stacks
pub const TLS_EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;

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
    0x0015, // padding (RFC 7685): covariant with ClientHello size
    0x0019, // cached_info (RFC 7924)
    0x0020, // ticket_pinning (RFC 8672)
    0x0023, // session_ticket (RFC 5077 / 8446)
    0x0029, // pre_shared_key (RFC 8446)
    0x002a, // early_data (RFC 8446)
    0x002c, // cookie (RFC 8446): HelloRetryRequest only
    0x002d, // psk_key_exchange_modes (RFC 8446)
    0x003a, // ticket_request (RFC 9149)
];

/// Check if a value is a GREASE value according to RFC 8701
#[inline(always)]
pub(super) fn is_grease_value(value: u16) -> bool {
    TLS_GREASE_VALUES.contains(&value)
}

/// Filter out GREASE values from a list of u16 values
#[inline]
pub(super) fn filter_grease_values(values: &[u16]) -> Vec<u16> {
    values
        .iter()
        .filter(|&&v| !is_grease_value(v))
        .copied()
        .collect()
}

#[cfg(feature = "stable-v1")]
#[inline]
pub(super) fn is_s1_session_extension(id: u16) -> bool {
    S1_SESSION_EXTENSIONS.binary_search(&id).is_ok()
}

#[cfg(feature = "stable-v1")]
pub(super) fn filter_s1_extensions(values: &[u16]) -> Cow<'_, [u16]> {
    if values.iter().any(|&v| is_s1_session_extension(v)) {
        Cow::Owned(
            values
                .iter()
                .copied()
                .filter(|&v| !is_s1_session_extension(v))
                .collect(),
        )
    } else {
        Cow::Borrowed(values)
    }
}
