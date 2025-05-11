use crate::fingerprint_traits::{
    DatabaseSignature, FingerprintDb, MatchQuality, ObservedFingerprint,
};
use crate::http::{self, Version as HttpVersion};
use crate::tcp::{self, IpVersion, PayloadSize};
use std::collections::HashMap;
use std::fmt;
use std::marker::PhantomData;
use tracing::error;

/// Represents the database used by `P0f` to store signatures and associated metadata.
/// The database contains signatures for analyzing TCP and HTTP traffic, as well as
/// other metadata such as MTU mappings and user agent-to-operating system mappings.
#[derive(Debug)]
pub struct Database {
    pub classes: Vec<String>,
    pub mtu: Vec<(String, Vec<u16>)>,
    pub ua_os: Vec<(String, Option<String>)>,
    pub tcp_request: FingerprintCollection<crate::tcp::Signature, crate::tcp::Signature>,
    pub tcp_response: FingerprintCollection<crate::tcp::Signature, crate::tcp::Signature>,
    pub http_request: FingerprintCollection<crate::http::Signature, crate::http::Signature>,
    pub http_response: FingerprintCollection<crate::http::Signature, crate::http::Signature>,
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

impl Database {
    /// Creates a new instance of the `Database`.
    ///
    /// # Arguments
    ///
    /// * `config_path` - An optional path to a configuration file. If `None`, the default
    ///   configuration file is used.
    ///
    /// # Returns
    /// A `Database` instance initialized with the provided or default configuration.
    pub fn new(config_path: Option<&str>) -> Self {
        if let Some(path) = config_path {
            std::fs::read_to_string(path)
                .ok()
                .and_then(|content| content.parse().ok())
                .unwrap_or_else(|| {
                    error!(
                        "Failed to load configuration from {}. Falling back to default.",
                        path
                    );
                    Self::default()
                })
        } else {
            Self::default()
        }
    }
}

impl Default for Database {
    /// Creates a default instance of the `Database` by parsing a configuration file
    /// located at `config/p0f.fp`. This file is expected to define the default
    /// signatures and mappings used for analysis.
    fn default() -> Self {
        include_str!("../config/p0f.fp")
            .parse()
            .expect("parse default database")
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
    ip_version: IpVersion,
    olayout_key: String, // String representation of TCP options, e.g., "mss,sok,ts"
    pclass: PayloadSize,
    // Note: TTL could be added later if it provides significant benefits,
    // but it adds complexity due to its varied representation (exact, range, wildcard).
}

impl TcpP0fIndexKey {
    /// Creates an index key from a TCP signature.
    ///
    /// When `specific_ip_ver_for_key` is Some (e.g., V4 or V6), it's used to create
    /// a specific key, typically for database signatures with `IpVersion::Any`.
    /// When None, the signature's own IP version is used (for observed signatures).
    fn from_tcp_sig(sig: &tcp::Signature, specific_ip_ver_for_key: Option<IpVersion>) -> Self {
        // Create a stable string representation for olayout
        // Sorting ensures that "sok,mss" and "mss,sok" produce the same key part if order doesn't matter for the key.
        // However, p0f olayout *is* order-sensitive for matching. For an index key,
        // we need to decide if the key itself should be order-sensitive or if we normalize.
        // p0f matching IS order sensitive for olayout. So the key should be.
        let olayout_parts: Vec<String> = sig.olayout.iter().map(|opt| format!("{}", opt)).collect();

        let ip_version_to_use = specific_ip_ver_for_key.unwrap_or(sig.version);

        Self {
            ip_version: ip_version_to_use,
            olayout_key: olayout_parts.join(","), // Order-sensitive key
            pclass: sig.pclass,
        }
    }
}

/// Index key for HTTP p0f signatures.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpP0fIndexKey {
    http_version: HttpVersion,
    expsw_key: String, // The 'expsw' field (e.g., "Apache", "Firefox/")
                       // Consider adding a digest of horder if needed for more granularity,
                       // but expsw is often a strong primary differentiator in p0f HTTP sigs.
}

impl HttpP0fIndexKey {
    /// Creates an index key from an HTTP signature.
    fn from_http_sig(
        sig: &http::Signature,
        specific_http_ver_for_key: Option<HttpVersion>,
    ) -> Self {
        let version_to_use = specific_http_ver_for_key.unwrap_or(sig.version);
        Self {
            http_version: version_to_use,
            // For expsw, we might want to handle cases like "Apache/2.2" vs "Apache".
            // p0f often uses just the prefix. For now, direct string, but could be normalized.
            expsw_key: sig.expsw.clone(), // Cloning the string. Might optimize later if it's a bottleneck.
        }
    }
}

#[derive(Debug)]
pub struct FingerprintCollection<OF, DS>
where
    OF: ObservedFingerprint,
    DS: DatabaseSignature<OF>,
{
    pub entries: Vec<(Label, Vec<DS>)>,
    /// Index for TCP signatures. `Option` allows this struct to be used for HTTP signatures too, where it would be `None`.
    /// The `Vec<(usize, usize)>` stores `(label_index, signature_index_within_that_label_in_entries)`.
    pub(crate) tcp_p0f_index: Option<HashMap<TcpP0fIndexKey, Vec<(usize, usize)>>>,
    pub(crate) http_p0f_index: Option<HashMap<HttpP0fIndexKey, Vec<(usize, usize)>>>,
    _observed_marker: PhantomData<OF>,
    _database_sig_marker: PhantomData<DS>,
}

impl<OF, DS> Default for FingerprintCollection<OF, DS>
where
    OF: ObservedFingerprint,
    DS: DatabaseSignature<OF>,
{
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            tcp_p0f_index: None,
            http_p0f_index: None,
            _observed_marker: PhantomData,
            _database_sig_marker: PhantomData,
        }
    }
}

impl FingerprintCollection<tcp::Signature, tcp::Signature> {
    /// Constructor for TCP signature collections, which builds the index.
    pub fn new_tcp_collection(entries: Vec<(Label, Vec<tcp::Signature>)>) -> Self {
        let mut index = HashMap::new();
        for (label_idx, (_label, sig_vec)) in entries.iter().enumerate() {
            for (sig_idx, db_sig) in sig_vec.iter().enumerate() {
                if db_sig.version == IpVersion::Any {
                    let key_v4 = TcpP0fIndexKey::from_tcp_sig(db_sig, Some(IpVersion::V4));
                    index
                        .entry(key_v4)
                        .or_insert_with(Vec::new)
                        .push((label_idx, sig_idx));

                    let key_v6 = TcpP0fIndexKey::from_tcp_sig(db_sig, Some(IpVersion::V6));
                    index
                        .entry(key_v6)
                        .or_insert_with(Vec::new)
                        .push((label_idx, sig_idx));
                } else {
                    let key = TcpP0fIndexKey::from_tcp_sig(db_sig, None);
                    index
                        .entry(key)
                        .or_insert_with(Vec::new)
                        .push((label_idx, sig_idx));
                }
            }
        }
        FingerprintCollection {
            entries,
            tcp_p0f_index: Some(index),
            http_p0f_index: None,
            _observed_marker: PhantomData,
            _database_sig_marker: PhantomData,
        }
    }
}

impl FingerprintCollection<http::Signature, http::Signature> {
    /// Constructor for HTTP signature collections, which builds the HTTP index.
    pub fn new_http_collection(entries: Vec<(Label, Vec<http::Signature>)>) -> Self {
        let mut index = HashMap::new();
        for (label_idx, (_label, sig_vec)) in entries.iter().enumerate() {
            for (sig_idx, db_sig) in sig_vec.iter().enumerate() {
                if db_sig.version == HttpVersion::Any {
                    let key_v10 = HttpP0fIndexKey::from_http_sig(db_sig, Some(HttpVersion::V10));
                    index
                        .entry(key_v10)
                        .or_insert_with(Vec::new)
                        .push((label_idx, sig_idx));

                    let key_v11 = HttpP0fIndexKey::from_http_sig(db_sig, Some(HttpVersion::V11));
                    index
                        .entry(key_v11)
                        .or_insert_with(Vec::new)
                        .push((label_idx, sig_idx));
                } else {
                    let key = HttpP0fIndexKey::from_http_sig(db_sig, None);
                    index
                        .entry(key)
                        .or_insert_with(Vec::new)
                        .push((label_idx, sig_idx));
                }
            }
        }
        FingerprintCollection {
            entries,
            tcp_p0f_index: None,
            http_p0f_index: Some(index),
            _observed_marker: PhantomData,
            _database_sig_marker: PhantomData,
        }
    }
}

impl<OF, DS> FingerprintCollection<OF, DS>
where
    OF: ObservedFingerprint,
    DS: DatabaseSignature<OF>,
{
    /// Generic constructor for collections where no special index is built,
    /// or for types not yet specialized (e.g. if we had a third signature type).
    pub fn new_generic_collection(entries: Vec<(Label, Vec<DS>)>) -> Self {
        FingerprintCollection {
            entries,
            tcp_p0f_index: None,
            http_p0f_index: None,
            _observed_marker: PhantomData,
            _database_sig_marker: PhantomData,
        }
    }

    pub(crate) fn get_quality_from_distance(distance: u32) -> MatchQuality {
        (100_u32.saturating_sub(distance)) as f32 / 100.0
    }
}

// Specialized implementation for TCP signatures using the TCP index
impl FingerprintDb<tcp::Signature, tcp::Signature>
    for FingerprintCollection<tcp::Signature, tcp::Signature>
{
    fn find_best_match(
        &self,
        observed: &tcp::Signature,
    ) -> Option<(&Label, &tcp::Signature, MatchQuality)> {
        tracing::debug!("Using TCP indexed scan for find_best_match");

        let index = self.tcp_p0f_index.as_ref().expect(
            "TCP index missing in FingerprintCollection<tcp::Signature, tcp::Signature>. \
            Ensure it's constructed with new_tcp_collection.",
        );

        let observed_key = TcpP0fIndexKey::from_tcp_sig(observed, None);
        let candidate_indices = match index.get(&observed_key) {
            Some(indices) => indices,
            None => {
                tracing::debug!(
                    "No candidates found for key {:?} in TCP index.",
                    observed_key
                );
                return None;
            }
        };

        if candidate_indices.is_empty() {
            tracing::debug!("Candidate list for key {:?} is empty.", observed_key);
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

// Specialized implementation for HTTP signatures using the HTTP index
impl FingerprintDb<http::Signature, http::Signature>
    for FingerprintCollection<http::Signature, http::Signature>
{
    fn find_best_match(
        &self,
        observed: &http::Signature,
    ) -> Option<(&Label, &http::Signature, MatchQuality)> {
        let index = self.http_p0f_index.as_ref().expect(
            "HTTP index missing in FingerprintCollection<http::Signature, http::Signature>. \
            Ensure it's constructed with new_http_collection.",
        );

        let observed_key = HttpP0fIndexKey::from_http_sig(observed, None);

        let candidate_indices = match index.get(&observed_key) {
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
