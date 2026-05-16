use crate::db_matching_trait::{DatabaseSignature, FingerprintDb, IndexKey, ObservedFingerprint};
#[cfg(feature = "http")]
use crate::http::{self, Version as HttpVersion};
#[cfg(feature = "tcp")]
use crate::observable_signals::TcpObservation;
#[cfg(feature = "http")]
use crate::observable_signals::{HttpRequestObservation, HttpResponseObservation};
#[cfg(feature = "tcp")]
use crate::tcp::{self, IpVersion, PayloadSize};
use std::collections::HashMap;
use std::fmt;
use std::fmt::Display;
use std::marker::PhantomData;
#[cfg(any(feature = "tcp", feature = "http"))]
use std::str::FromStr;
use tracing::debug;

/// TCP-only fingerprint database: IP/TCP (layer-3/4) signatures plus MTU mappings.
///
/// Holds everything needed to match observed TCP traffic against the p0f
/// database. Independent of HTTP signatures, can be loaded and used on its
/// own (see `Database::from_str` for the composed `Database` parser).
#[cfg(feature = "tcp")]
#[derive(Debug, Clone)]
pub struct TcpDatabase {
    pub classes: Vec<String>,
    pub mtu: Vec<(String, Vec<u16>)>,
    pub tcp_request: FingerprintCollection<TcpObservation, tcp::Signature, TcpIndexKey>,
    pub tcp_response: FingerprintCollection<TcpObservation, tcp::Signature, TcpIndexKey>,
}

/// HTTP-only fingerprint database: HTTP (layer-7) signatures plus User-Agent → OS mappings.
///
/// Holds everything needed to match observed HTTP traffic against the p0f
/// database. Independent of TCP signatures, can be loaded and used on its
/// own (see `Database::from_str` for the composed `Database` parser).
#[cfg(feature = "http")]
#[derive(Debug, Clone)]
pub struct HttpDatabase {
    pub classes: Vec<String>,
    pub ua_os: Vec<(String, Option<String>)>,
    pub http_request: FingerprintCollection<HttpRequestObservation, http::Signature, HttpIndexKey>,
    pub http_response:
        FingerprintCollection<HttpResponseObservation, http::Signature, HttpIndexKey>,
}

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

/// Represents a label associated with a signature, which provides metadata about
/// the signature, such as type, class, name, and optional flavor details.
#[derive(Clone, Debug, PartialEq)]
pub struct Label {
    pub ty: Type,
    pub class: Option<String>,
    pub name: String,
    pub flavor: Option<String>,
}

/// Enum representing the type of `Label`.
/// - `Specified`: A specific label with well-defined characteristics.
/// - `Generic`: A generic label with broader characteristics.
#[derive(Clone, Debug, PartialEq)]
pub enum Type {
    Specified,
    Generic,
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Bytes of the bundled p0f fingerprint database, embedded at build time.
#[cfg(any(feature = "tcp", feature = "http"))]
pub(crate) const DEFAULT_FP_CONTENTS: &str = include_str!("../config/p0f.fp");

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

/// Index key for TCP signatures, used to optimize database lookups.
///
/// This key is generated from a `tcp::Signature` and combines several
/// of its most discriminative fields to allow for a fast initial filtering
/// of potential matches in the signature database. The goal is to quickly
/// narrow down the search space before performing more detailed and costly
/// distance calculations.
///
/// The fields included are chosen for their balance of providing good
/// discrimination while not being overly specific to avoid missing matches
/// due to minor variations (which are handled by the distance calculation).
#[cfg(feature = "tcp")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TcpIndexKey {
    pub ip_version_key: IpVersion,
    pub olayout_key: String,
    pub pclass_key: PayloadSize,
}

#[cfg(feature = "tcp")]
impl IndexKey for TcpIndexKey {}

/// Index key for HTTP signatures, used to optimize database lookups.
///
/// This key is generated from a `http::Signature`
/// to enable faster filtering of HTTP signatures. It combines key characteristics
/// of an HTTP request or response.
#[cfg(feature = "http")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpIndexKey {
    pub http_version_key: HttpVersion,
}

#[cfg(feature = "http")]
impl IndexKey for HttpIndexKey {}

#[derive(Debug, Clone)]
pub struct FingerprintCollection<OF, DS, K>
where
    OF: ObservedFingerprint<Key = K>,
    DS: DatabaseSignature<OF>,
    K: IndexKey,
{
    pub entries: Vec<(Label, Vec<DS>)>,
    pub(crate) index: HashMap<K, Vec<(usize, usize)>>,
    _observed_marker: PhantomData<OF>,
    _database_sig_marker: PhantomData<DS>,
    _key_marker: PhantomData<K>,
}

impl<OF, DS, K> Default for FingerprintCollection<OF, DS, K>
where
    OF: ObservedFingerprint<Key = K>,
    DS: DatabaseSignature<OF>,
    K: IndexKey,
{
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            index: HashMap::new(),
            _observed_marker: PhantomData,
            _database_sig_marker: PhantomData,
            _key_marker: PhantomData,
        }
    }
}

impl<OF, DS, K> FingerprintCollection<OF, DS, K>
where
    OF: ObservedFingerprint<Key = K>,
    DS: DatabaseSignature<OF>,
    K: IndexKey,
{
    /// Creates a new collection and builds an index for it.
    pub fn new(entries: Vec<(Label, Vec<DS>)>) -> Self {
        let mut index_map = HashMap::new();
        for (label_idx, (_label, sig_vec)) in entries.iter().enumerate() {
            for (sig_idx, db_sig) in sig_vec.iter().enumerate() {
                for key in db_sig.generate_index_keys_for_db_entry() {
                    index_map
                        .entry(key)
                        .or_insert_with(Vec::new)
                        .push((label_idx, sig_idx));
                }
            }
        }
        FingerprintCollection {
            entries,
            index: index_map,
            _observed_marker: PhantomData,
            _database_sig_marker: PhantomData,
            _key_marker: PhantomData,
        }
    }
}

impl<OF, DS, K> FingerprintDb<OF, DS> for FingerprintCollection<OF, DS, K>
where
    OF: ObservedFingerprint<Key = K>,
    DS: DatabaseSignature<OF> + Display,
    K: IndexKey,
{
    fn find_best_match(&self, observed: &OF) -> Option<(&Label, &DS, f32)> {
        let observed_key = observed.generate_index_key();

        let candidate_indices = match self.index.get(&observed_key) {
            Some(indices) => indices,
            None => {
                return None;
            }
        };

        if candidate_indices.is_empty() {
            return None;
        }

        let mut best_label_ref = None;
        let mut best_sig_ref = None;
        let mut min_distance = u32::MAX;

        for &(label_idx, sig_idx) in candidate_indices {
            let (label, sig_vec) = &self.entries[label_idx];
            let db_sig = &sig_vec[sig_idx];

            if let Some(distance) = db_sig.calculate_distance(observed) {
                if distance < min_distance {
                    min_distance = distance;
                    best_label_ref = Some(label);
                    best_sig_ref = Some(db_sig);
                }
                debug!(
                    "distance: {}, label: {}, flavor: {:?}, sig: {}",
                    distance, label.name, label.flavor, db_sig
                );
            }
        }

        if let (Some(label), Some(sig)) = (best_label_ref, best_sig_ref) {
            Some((label, sig, sig.get_quality_score(min_distance)))
        } else {
            None
        }
    }
}
