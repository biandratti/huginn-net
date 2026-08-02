//! Fingerprint collection and index-based matching.

use crate::database::label::{Label, Type};
use crate::db_matching_trait::{
    DatabaseMatch, DatabaseSignature, FingerprintDb, IndexKey, MatchRank, ObservedFingerprint,
};
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

    /// Buckets of `(label_idx, sig_idx)` in declaration order, for coverage checks.
    pub(crate) fn index_buckets(&self) -> impl Iterator<Item = (&K, &Vec<(usize, usize)>)> {
        self.index.iter()
    }
}

impl<OF, DS, K> FingerprintDb<OF, DS> for FingerprintCollection<OF, DS, K>
where
    OF: ObservedFingerprint<Key = K>,
    DS: DatabaseSignature<OF> + Display,
    K: IndexKey,
{
    /// p0f selection (`fp_tcp.c:221-271`): return the first specific-exact fit;
    /// otherwise the first generic-exact; otherwise the first fuzzy — except a
    /// fuzzy fit against a userland tool (`label.class == None`) is discarded
    /// and yields no match.
    fn find_best_match(&self, observed: &OF) -> Option<DatabaseMatch<'_, DS, DS::Fuzziness>> {
        let observed_key = observed.generate_index_key();
        let candidate_indices = self.index.get(&observed_key)?;

        let mut gmatch: Option<(&Label, &DS)> = None;
        let mut fmatch: Option<(&Label, &DS, DS::Fuzziness)> = None;

        for &(label_idx, sig_idx) in candidate_indices {
            let (label, sig_vec) = &self.entries[label_idx];
            let db_sig = &sig_vec[sig_idx];

            let Some(fit) = db_sig.fit(observed) else {
                continue;
            };

            if fit.fuzzy.is_none() {
                match label.ty {
                    Type::Specified => {
                        debug!(
                            "fit: Specific (early exit), label: {}, flavor: {:?}, sig: {db_sig}",
                            label.name, label.flavor
                        );
                        return Some(DatabaseMatch {
                            label,
                            signature: db_sig,
                            quality: MatchRank::Specific.as_quality(),
                            fuzzy: None,
                        });
                    }
                    Type::Generic => {
                        if gmatch.is_none() {
                            debug!(
                                "fit: Generic (remembered), label: {}, flavor: {:?}, sig: {db_sig}",
                                label.name, label.flavor
                            );
                            gmatch = Some((label, db_sig));
                        }
                    }
                }
            } else if let (None, Some(reason)) = (&fmatch, fit.fuzzy) {
                // First fuzzy wins the slot, including userland tools; whether
                // it is reported is decided after the bucket is exhausted.
                debug!(
                    "fit: Fuzzy (remembered), label: {}, flavor: {:?}, sig: {db_sig}",
                    label.name, label.flavor
                );
                fmatch = Some((label, db_sig, reason));
            }
        }

        if let Some((label, signature)) = gmatch {
            return Some(DatabaseMatch {
                label,
                signature,
                quality: MatchRank::Generic.as_quality(),
                fuzzy: None,
            });
        }

        if let Some((label, signature, fuzzy)) = fmatch {
            // p0f: "No fuzzy matching for userland tools." (`fp_tcp.c:256`)
            label.class.as_ref()?;
            return Some(DatabaseMatch {
                label,
                signature,
                quality: MatchRank::Fuzzy.as_quality(),
                fuzzy: Some(fuzzy),
            });
        }

        None
    }
}
