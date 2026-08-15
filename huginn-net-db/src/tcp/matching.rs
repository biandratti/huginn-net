//! Glue between [`huginn_net_tcp::observable::TcpObservation`] and the
//! database matcher infrastructure.

use crate::database::TcpIndexKey;
use crate::db_matching_trait::{DatabaseSignature, ObservedFingerprint, SignatureFit};
use crate::tcp::{
    self, ip_version_matches, payload_size_matches, ttl_fit, window_size_matches, IpVersion,
    PayloadSize, QuirkSet,
};
use huginn_net_tcp::observable::TcpObservation;
use huginn_net_tcp::output::FuzzyReason;
use huginn_net_tcp::tcp::hash_olayout;

/// `olen` is never wildcarded in p0f's format: a mismatch is a hard reject.
pub(crate) fn olen_matches(observed: &TcpObservation, signature: &tcp::Signature) -> bool {
    observed.olen == signature.olen
}

/// A signature-specified `mss` is a hard gate in p0f: only `mss == *`
/// (wildcard, `None` here) tolerates any observed value.
pub(crate) fn mss_matches(observed: &TcpObservation, signature: &tcp::Signature) -> bool {
    signature.mss.is_none() || observed.mss == signature.mss
}

/// A signature-specified `wscale` is a hard gate in p0f: only `wscale == *`
/// (wildcard, `None` here) tolerates any observed value.
pub(crate) fn wscale_matches(observed: &TcpObservation, signature: &tcp::Signature) -> bool {
    signature.wscale.is_none() || observed.wscale == signature.wscale
}

pub(crate) fn olayout_matches(observed: &TcpObservation, signature: &tcp::Signature) -> bool {
    observed.olayout == signature.olayout
}

/// The quirks that had to be tolerated for a signature to hold. Empty on both
/// sides when the sets agreed exactly.
#[derive(Debug, Default)]
pub(crate) struct QuirksFit {
    /// Shown by the traffic, not declared by the signature.
    pub added: QuirkSet,
    /// Declared by the signature, not shown by the traffic.
    pub missing: QuirkSet,
}

impl QuirksFit {
    fn is_exact(&self) -> bool {
        self.added.is_empty() && self.missing.is_empty()
    }
}

/// Apply p0f's version-agnostic quirk mask (`fp_tcp.c:140-141`): when the
/// signature is `ver == *`, drop quirks that only exist on the other IP family.
fn mask_signature_quirks(
    sig_quirks: QuirkSet,
    sig_version: IpVersion,
    obs_version: IpVersion,
) -> QuirkSet {
    if sig_version != IpVersion::Any {
        return sig_quirks;
    }
    match obs_version {
        IpVersion::V4 => sig_quirks & !QuirkSet::MASK_WHEN_OBS_V4,
        IpVersion::V6 => sig_quirks & !QuirkSet::MASK_WHEN_OBS_V6,
        IpVersion::Any => sig_quirks,
    }
}

/// Quirks are compared as bitmasks, and a narrow set of differences is
/// tolerated as a fuzzy match: `df`/`id+` may be absent from the traffic, and
/// `id-`/`ecn` may appear in it. Any other difference rejects the signature.
///
/// Returns which quirks the tolerance had to cover; `None` rejects.
pub(crate) fn quirks_fit(
    observed: &TcpObservation,
    signature: &tcp::Signature,
) -> Option<QuirksFit> {
    let sig = mask_signature_quirks(signature.quirks, signature.version, observed.version);
    let obs = observed.quirks;

    let missing = sig.difference(obs);
    let added = obs.difference(sig);

    if !missing.difference(QuirkSet::FUZZY_DELETABLE).is_empty() {
        return None;
    }
    if !added.difference(QuirkSet::FUZZY_ADDABLE).is_empty() {
        return None;
    }

    Some(QuirksFit { added, missing })
}

impl ObservedFingerprint for TcpObservation {
    type Key = TcpIndexKey;

    fn generate_index_key(&self) -> Self::Key {
        TcpIndexKey {
            ip_version_key: self.version,
            olayout_hash: hash_olayout(&self.olayout),
            pclass_key: self.pclass,
        }
    }
}

impl DatabaseSignature<TcpObservation> for tcp::Signature {
    type Fuzziness = FuzzyReason;

    /// Seven of the nine fields are gates. `ttl` and `quirks` may be
    /// tolerated; either one (or both) makes the match fuzzy.
    fn fit(&self, observed: &TcpObservation) -> Option<SignatureFit<FuzzyReason>> {
        let gates = ip_version_matches(&observed.version, &self.version)
            && olen_matches(observed, self)
            && mss_matches(observed, self)
            && window_size_matches(observed.wsize, &self.wsize, observed.window_multiplier())
            && wscale_matches(observed, self)
            && olayout_matches(observed, self)
            && payload_size_matches(&observed.pclass, &self.pclass);

        if !gates {
            return None;
        }

        let ttl = ttl_fit(&observed.ittl, &self.ittl)?;
        let quirks = quirks_fit(observed, self)?;

        if !ttl.out_of_range && quirks.is_exact() {
            return Some(SignatureFit::exact());
        }

        let reason = FuzzyReason {
            implausible_hop_distance: ttl.out_of_range.then_some(ttl.hop_distance),
            added_quirks: quirks.added,
            missing_quirks: quirks.missing,
        };
        Some(SignatureFit::fuzzy(reason))
    }

    fn generate_index_keys_for_db_entry(&self) -> Vec<TcpIndexKey> {
        let mut keys = Vec::new();
        let olayout_hash = hash_olayout(&self.olayout);

        let versions_for_keys: &[IpVersion] = if self.version == IpVersion::Any {
            &[IpVersion::V4, IpVersion::V6]
        } else {
            std::slice::from_ref(&self.version)
        };

        let pclasses_for_keys: &[PayloadSize] = if self.pclass == PayloadSize::Any {
            &[PayloadSize::Zero, PayloadSize::NonZero]
        } else {
            std::slice::from_ref(&self.pclass)
        };

        for &v_key_part in versions_for_keys {
            for &pc_key_part in pclasses_for_keys {
                keys.push(TcpIndexKey {
                    ip_version_key: v_key_part,
                    olayout_hash,
                    pclass_key: pc_key_part,
                });
            }
        }

        keys
    }
}
