use crate::fingerprint_traits::{
    DatabaseSignature, FingerprintDb, IndexKey, MatchQuality, ObservedFingerprint,
};
use crate::http::{self, Version as HttpVersion};
use crate::tcp::{self, IpVersion, PayloadSize};
use std::collections::HashMap;
use std::fmt;
use std::fmt::Display;
use std::marker::PhantomData;
use std::str::FromStr;

/// Represents the database used by `P0f` to store signatures and associated metadata.
/// The database contains signatures for analyzing TCP and HTTP traffic, as well as
/// other metadata such as MTU mappings and user agent-to-operating system mappings.
#[derive(Debug)]
pub struct Database {
    pub classes: Vec<String>,
    pub mtu: Vec<(String, Vec<u16>)>,
    pub ua_os: Vec<(String, Option<String>)>,
    pub tcp_request: FingerprintCollection<tcp::Signature, tcp::Signature, TcpP0fIndexKey>,
    pub tcp_response: FingerprintCollection<tcp::Signature, tcp::Signature, TcpP0fIndexKey>,
    pub http_request: FingerprintCollection<http::Signature, http::Signature, HttpP0fIndexKey>,
    pub http_response: FingerprintCollection<http::Signature, http::Signature, HttpP0fIndexKey>,
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
        write!(f, "{:?}", self)
    }
}

impl Default for Database {
    /// Creates a default instance of the `Database` by parsing an embedded configuration file.
    /// This file (`config/p0f.fp` relative to the crate root) is expected to define the default
    /// signatures and mappings used for analysis.
    ///
    /// # Panics
    /// Panic if the embedded default fingerprint file cannot be parsed. This indicates
    /// a critical issue with the bundled fingerprint data or the parser itself.
    fn default() -> Self {
        const DEFAULT_FP_CONTENTS: &str = include_str!("../config/p0f.fp");
        
        match Database::from_str(DEFAULT_FP_CONTENTS) {
            Ok(db) => db,
            Err(e) => {
                panic!(
                    "CRITICAL: Failed to parse embedded default fingerprint file. This is a bug or a corrupted built-in DB. Error: {}",
                    e
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::db::Database;

    #[test]
    fn test_default_database() {
        let db = Database::default();

        assert_eq!(db.classes, vec!["win", "unix", "other"]);

        assert_eq!(
            db.mtu,
            vec![
                ("Ethernet or modem".to_owned(), vec![576, 1500]),
                ("DSL".to_owned(), vec![1452, 1454, 1492]),
                ("GIF".to_owned(), vec![1240, 1280]),
                (
                    "generic tunnel or VPN".to_owned(),
                    vec![1300, 1400, 1420, 1440, 1450, 1460]
                ),
                ("IPSec or GRE".to_owned(), vec![1476]),
                ("IPIP or SIT".to_owned(), vec![1480]),
                ("PPTP".to_owned(), vec![1490]),
                ("AX.25 radio modem".to_owned(), vec![256]),
                ("SLIP".to_owned(), vec![552]),
                ("Google".to_owned(), vec![1470]),
                ("VLAN".to_owned(), vec![1496]),
                ("Ericsson HIS modem".to_owned(), vec![1656]),
                ("jumbo Ethernet".to_owned(), vec![9000]),
                ("loopback".to_owned(), vec![3924, 16384, 16436])
            ]
        );
    }
}

/// Index key for TCP p0f signatures, used to optimize lookups.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TcpP0fIndexKey {
    pub ip_version: IpVersion,
    pub olayout_key: String,
    pub pclass: PayloadSize,
}

impl IndexKey for TcpP0fIndexKey {}

/// Index key for HTTP p0f signatures.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpP0fIndexKey {
    pub http_version: HttpVersion,
    pub expsw_key: String,
}

impl IndexKey for HttpP0fIndexKey {}

#[derive(Debug)]
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

    pub(crate) fn get_quality_from_distance(distance: u32) -> MatchQuality {
        (100_u32.saturating_sub(distance)) as f32 / 100.0
    }
}

impl<OF, DS, K> FingerprintDb<OF, DS> for FingerprintCollection<OF, DS, K>
where
    OF: ObservedFingerprint<Key = K>,
    DS: DatabaseSignature<OF> + Display,
    K: IndexKey,
{
    fn find_best_match(&self, observed: &OF) -> Option<(&Label, &DS, MatchQuality)> {
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
            }
        }

        if let (Some(label), Some(sig)) = (best_label_ref, best_sig_ref) {
            Some((label, sig, Self::get_quality_from_distance(min_distance)))
        } else {
            None
        }
    }
}
