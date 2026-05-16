//! HTTP-only fingerprint database.

use std::str::FromStr;

use crate::database::collection::FingerprintCollection;
use crate::database::constants::DEFAULT_FP_CONTENTS;
use crate::database::keys::HttpIndexKey;
use crate::http;
use crate::observable_signals::{HttpRequestObservation, HttpResponseObservation};

/// HTTP-only fingerprint database: HTTP (layer-7) signatures plus User-Agent → OS mappings.
///
/// Holds everything needed to match observed HTTP traffic against the p0f
/// database. Independent of TCP signatures, can be loaded and used on its
/// own (see [`crate::Database`] for the composed database parser when both features are enabled).
#[cfg(feature = "http")]
#[derive(Debug, Clone)]
pub struct HttpDatabase {
    pub classes: Vec<String>,
    pub ua_os: Vec<(String, Option<String>)>,
    pub http_request: FingerprintCollection<HttpRequestObservation, http::Signature, HttpIndexKey>,
    pub http_response:
        FingerprintCollection<HttpResponseObservation, http::Signature, HttpIndexKey>,
}

#[cfg(feature = "http")]
impl HttpDatabase {
    /// Load only the HTTP sub-database from the embedded `p0f.fp`.
    pub fn load_default() -> Result<Self, crate::error::DatabaseError> {
        HttpDatabase::from_str(DEFAULT_FP_CONTENTS).map_err(|e| {
            crate::error::DatabaseError::InvalidConfiguration(format!(
                "Failed to parse embedded default p0f database: {e}"
            ))
        })
    }
}
