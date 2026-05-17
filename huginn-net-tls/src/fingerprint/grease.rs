#[cfg(feature = "stable-v1")]
use std::borrow::Cow;

/// See <https://datatracker.ietf.org/doc/html/draft-davidben-tls-grease-01#page-5>
pub const TLS_GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// TLS Session Ticket extension (RFC 9149): ephemeral, varies per-connection
pub const TLS_EXT_SESSION_TICKET: u16 = 0x0023;
/// Pre-Shared Key extension (RFC 8446): ephemeral, varies per-connection
pub const TLS_EXT_PRE_SHARED_KEY: u16 = 0x0029;
/// Padding extension (RFC 7685): ephemeral, varies per-connection
pub const TLS_EXT_PADDING: u16 = 0x0015;

/// Ephemeral TLS extensions that may vary per-connection and break JA4 stability
pub const EPHEMERAL_TLS_EXTENSIONS: [u16; 3] =
    [TLS_EXT_SESSION_TICKET, TLS_EXT_PRE_SHARED_KEY, TLS_EXT_PADDING];

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
pub(super) fn filter_ephemeral_extensions(values: &[u16]) -> Cow<'_, [u16]> {
    if values
        .iter()
        .any(|v| matches!(v, &TLS_EXT_SESSION_TICKET | &TLS_EXT_PRE_SHARED_KEY | &TLS_EXT_PADDING))
    {
        Cow::Owned(
            values
                .iter()
                .copied()
                .filter(|v| {
                    !matches!(
                        v,
                        &TLS_EXT_SESSION_TICKET | &TLS_EXT_PRE_SHARED_KEY | &TLS_EXT_PADDING
                    )
                })
                .collect(),
        )
    } else {
        Cow::Borrowed(values)
    }
}
