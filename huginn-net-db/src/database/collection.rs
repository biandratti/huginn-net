//! Fingerprint collection and index-based matching.

use crate::database::label::Label;
use crate::db_matching_trait::{DatabaseSignature, FingerprintDb, IndexKey, ObservedFingerprint};
use std::collections::HashMap;
use std::fmt::Display;
use std::marker::PhantomData;
use tracing::debug;

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
