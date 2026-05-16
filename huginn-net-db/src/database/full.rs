//! Composite p0f database (TCP + HTTP).

#[cfg(all(feature = "tcp", feature = "http"))]
use std::str::FromStr;

#[cfg(all(feature = "tcp", feature = "http"))]
use crate::database::constants::DEFAULT_FP_CONTENTS;
#[cfg(all(feature = "tcp", feature = "http"))]
use crate::database::http::HttpDatabase;
#[cfg(all(feature = "tcp", feature = "http"))]
use crate::database::tcp::TcpDatabase;

/// Composite p0f database holding both TCP and HTTP sub-databases.
///
/// `Database` is the public-facing type loaded from `p0f.fp` (or any
/// equivalent text). It is a thin composition of [`TcpDatabase`] and
/// [`HttpDatabase`]; consumers can also work with each sub-database
/// directly when they only need one protocol.
///
/// Available only when both `tcp` and `http` features are enabled.
#[cfg(all(feature = "tcp", feature = "http"))]
#[derive(Debug, Clone)]
pub struct Database {
    pub tcp: TcpDatabase,
    pub http: HttpDatabase,
}

#[cfg(all(feature = "tcp", feature = "http"))]
impl Database {
    /// Creates a default instance of the `Database` by parsing an embedded configuration file.
    /// This file (`config/p0f.fp` relative to the crate root) is expected to define the default
    /// signatures and mappings used for analysis.
    ///
    /// # Errors
    /// Returns `HuginnNetError::MissConfiguration` if the embedded default fingerprint file
    /// cannot be parsed. This indicates a critical issue with the bundled fingerprint data
    /// or the parser itself.
    pub fn load_default() -> Result<Self, crate::error::DatabaseError> {
        Database::from_str(DEFAULT_FP_CONTENTS).map_err(|e| {
            crate::error::DatabaseError::InvalidConfiguration(format!(
                "Failed to parse embedded default p0f database: {e}"
            ))
        })
    }
}
