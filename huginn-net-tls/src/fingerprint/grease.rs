#[cfg(feature = "stable-v1")]
use super::extensions::S1_SESSION_EXTENSIONS;
#[cfg(feature = "stable-v1")]
use std::borrow::Cow;

/// See <https://datatracker.ietf.org/doc/html/draft-davidben-tls-grease-01#page-5>
pub const TLS_GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
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
