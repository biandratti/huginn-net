//! Embedded default fingerprint database.

/// Bytes of the bundled p0f fingerprint database, embedded at build time.
#[cfg(any(feature = "tcp", feature = "http"))]
pub(crate) const DEFAULT_FP_CONTENTS: &str = include_str!("../../config/p0f.fp");
