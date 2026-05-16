//! TCP-only fingerprint database.

use std::str::FromStr;

use crate::database::collection::FingerprintCollection;
use crate::database::constants::DEFAULT_FP_CONTENTS;
use crate::database::keys::TcpIndexKey;
use crate::tcp;
use huginn_net_tcp::observable::TcpObservation;

/// TCP-only fingerprint database: IP/TCP (layer-3/4) signatures plus MTU mappings.
///
/// Holds everything needed to match observed TCP traffic against the p0f
/// database. Independent of HTTP signatures, can be loaded and used on its
/// own (see [`crate::Database`] for the composed database parser when both features are enabled).
#[cfg(feature = "tcp")]
#[derive(Debug, Clone)]
pub struct TcpDatabase {
    pub classes: Vec<String>,
    pub mtu: Vec<(String, Vec<u16>)>,
    pub tcp_request: FingerprintCollection<TcpObservation, tcp::Signature, TcpIndexKey>,
    pub tcp_response: FingerprintCollection<TcpObservation, tcp::Signature, TcpIndexKey>,
}

#[cfg(feature = "tcp")]
impl TcpDatabase {
    /// Load only the TCP sub-database from the embedded `p0f.fp`.
    pub fn load_default() -> Result<Self, crate::error::DatabaseError> {
        TcpDatabase::from_str(DEFAULT_FP_CONTENTS).map_err(|e| {
            crate::error::DatabaseError::InvalidConfiguration(format!(
                "Failed to parse embedded default p0f database: {e}"
            ))
        })
    }
}
