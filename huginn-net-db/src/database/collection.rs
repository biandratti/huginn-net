//! Fingerprint collection and index-based matching.

use crate::database::label::{Label, Type};
use crate::db_matching_trait::{
    DatabaseSignature, FingerprintDb, IndexKey, MatchRank, ObservedFingerprint, SignatureFit,
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
}

impl<OF, DS, K> FingerprintDb<OF, DS> for FingerprintCollection<OF, DS, K>
where
    OF: ObservedFingerprint<Key = K>,
    DS: DatabaseSignature<OF> + Display,
    K: IndexKey,
{
    fn find_best_match(&self, observed: &OF) -> Option<(&Label, &DS, f32)> {
        let observed_key = observed.generate_index_key();

        let candidate_indices = self.index.get(&observed_key)?;

        let mut best: Option<(&Label, &DS, MatchRank, u32)> = None;

        for &(label_idx, sig_idx) in candidate_indices {
            let (label, sig_vec) = &self.entries[label_idx];
            let db_sig = &sig_vec[sig_idx];

            let Some(fit) = db_sig.fit(observed) else {
                continue;
            };

            let Some(rank) = rank_of(label, fit) else {
                continue;
            };

            debug!(
                "fit: {rank:?} (deviation {}), label: {}, flavor: {:?}, sig: {db_sig}",
                fit.deviation, label.name, label.flavor
            );

            // Better rank wins outright; within a rank, the closer candidate
            // does. Ties keep the earlier entry, so a `.fp` still decides
            // between two equally good signatures by its own order.
            if best.is_none_or(|(_, _, best_rank, best_deviation)| {
                (rank, fit.deviation) < (best_rank, best_deviation)
            }) {
                best = Some((label, db_sig, rank, fit.deviation));
            }
        }

        best.map(|(label, sig, rank, _)| (label, sig, rank.as_quality()))
    }
}

/// Which tier a candidate lands in, or `None` when the fit is real but p0f
/// refuses to report it.
///
/// That refusal is p0f's "no fuzzy matching for userland tools"
/// (`fp_tcp.c:256`): guessing at an application from an approximate match is
/// worse than saying nothing, so an application signature — one whose label
/// declares no OS class — is only ever reported on an exact fit.
fn rank_of(label: &Label, fit: SignatureFit) -> Option<MatchRank> {
    if fit.fuzzy {
        return label.class.is_some().then_some(MatchRank::Fuzzy);
    }

    Some(match label.ty {
        Type::Specified => MatchRank::Specific,
        Type::Generic => MatchRank::Generic,
    })
}
