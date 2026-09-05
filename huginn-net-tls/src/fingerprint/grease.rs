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

/// Capability extension types hashed by `JA4_s1` (`feature = "stable-v1"`).
///
/// Sorted. Session / resumption types (`padding`, `session_ticket`,
/// `pre_shared_key`, `early_data`, `cookie`) and any unlisted ID are dropped.
/// Promoting an always-on ID is a breaking s1 bump.
///
/// `psk_key_exchange_modes` (0x002d) is included: Chrome/Safari send it on
/// every Hello. Stacks that emit it only with PSK will split s1.
#[cfg(feature = "stable-v1")]
#[cfg_attr(docsrs, doc(cfg(feature = "stable-v1")))]
pub const S1_EXTENSION_ALLOWLIST: &[u16] = &[
    0x0000, // server_name
    0x0005, // status_request
    0x000a, // supported_groups
    0x000b, // ec_point_formats
    0x000d, // signature_algorithms
    0x0010, // ALPN
    0x0012, // signed_certificate_timestamp
    0x0017, // extended_master_secret
    0x001b, // compress_certificate
    0x001c, // record_size_limit
    0x0022, // delegated_credential
    0x002b, // supported_versions
    0x002d, // psk_key_exchange_modes
    0x0031, // post_handshake_auth
    0x0032, // signature_algorithms_cert
    0x0033, // key_share
    0x4469, // ALPS (old)
    0x44cd, // ALPS
    0xfe0d, // ECH
    0xff01, // renegotiation_info
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
pub(super) fn is_s1_extension(id: u16) -> bool {
    S1_EXTENSION_ALLOWLIST.binary_search(&id).is_ok()
}

#[cfg(feature = "stable-v1")]
pub(super) fn filter_s1_extensions(values: &[u16]) -> Cow<'_, [u16]> {
    if values.iter().all(|&v| is_s1_extension(v)) {
        Cow::Borrowed(values)
    } else {
        Cow::Owned(
            values
                .iter()
                .copied()
                .filter(|&v| is_s1_extension(v))
                .collect(),
        )
    }
}
