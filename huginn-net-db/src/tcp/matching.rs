//! Glue between [`huginn_net_tcp::observable::TcpObservation`] and the
//! database matcher infrastructure.
//!
//! Provides:
//! - `pub(crate)` distance helpers that read fields off a `TcpObservation`
//!   (`distance_olen`, `distance_mss`, `distance_wscale`, `distance_olayout`,
//!   `distance_quirks`). The pure helpers that compare two raw signature
//!   types ([`crate::tcp::distance_ttl`], [`crate::tcp::distance_window_size`],
//!   …) live in `crate::tcp::distances` (private module; re-exported through
//!   [`crate::tcp`]).
//! - The [`crate::db_matching_trait::ObservedFingerprint`] impl that turns an
//!   observation into a [`crate::database::TcpIndexKey`].
//! - The [`crate::db_matching_trait::DatabaseSignature`] impl that scores a
//!   `tcp::Signature` against a `TcpObservation`.
//!
//! For backward compatibility this module is re-exposed at the crate root as
//! `huginn_net_db::observable_tcp_signals_matching` via a `#[path]` shim in
//! `lib.rs`.

use crate::database::TcpIndexKey;
use crate::db_matching_trait::{DatabaseSignature, MatchQuality, ObservedFingerprint};
use crate::tcp::{
    self, distance_ip_version, distance_payload_size, distance_ttl, distance_window_size,
    IpVersion, PayloadSize, Quirk,
};
use huginn_net_tcp::observable::TcpObservation;

/// `olen` is never wildcarded in p0f's format: a mismatch is a hard reject, not a soft penalty.
pub(crate) fn distance_olen(observed: &TcpObservation, signature: &tcp::Signature) -> Option<u32> {
    if observed.olen == signature.olen {
        Some(tcp::TcpMatchQuality::High.as_score())
    } else {
        None
    }
}

/// A signature-specified `mss` is a hard gate in p0f: only `mss == *`
/// (wildcard, `None` here) tolerates any observed value.
pub(crate) fn distance_mss(observed: &TcpObservation, signature: &tcp::Signature) -> Option<u32> {
    if signature.mss.is_none() || observed.mss == signature.mss {
        Some(tcp::TcpMatchQuality::High.as_score())
    } else {
        None
    }
}

/// A signature-specified `wscale` is a hard gate in p0f: only `wscale == *`
/// (wildcard, `None` here) tolerates any observed value.
pub(crate) fn distance_wscale(
    observed: &TcpObservation,
    signature: &tcp::Signature,
) -> Option<u32> {
    if signature.wscale.is_none() || observed.wscale == signature.wscale {
        Some(tcp::TcpMatchQuality::High.as_score())
    } else {
        None
    }
}

pub(crate) fn distance_olayout(
    observed: &TcpObservation,
    signature: &tcp::Signature,
) -> Option<u32> {
    if observed.olayout == signature.olayout {
        Some(tcp::TcpMatchQuality::High.as_score())
    } else {
        None
    }
}

/// Quirks a database signature may declare without the observation showing
/// them (`df` and `id+` in p0f terms).
const FUZZY_DELETABLE_QUIRKS: [Quirk; 2] = [Quirk::Df, Quirk::NonZeroID];

/// Quirks an observation may show without the database signature declaring
/// them (`id-` and `ecn` in p0f terms).
const FUZZY_ADDABLE_QUIRKS: [Quirk; 2] = [Quirk::ZeroID, Quirk::Ecn];

/// Whether a database quirk must be ignored because the signature is
/// version-agnostic (`ver == *`) and the quirk only exists for the other IP
/// version. Mirrors the `ref_quirks &= …` masking p0f applies before
/// comparing.
fn quirk_masked_by_ip_version(
    quirk: &Quirk,
    signature_version: IpVersion,
    observed_version: IpVersion,
) -> bool {
    if signature_version != IpVersion::Any {
        return false;
    }
    match observed_version {
        IpVersion::V6 => matches!(quirk, Quirk::Df | Quirk::NonZeroID | Quirk::ZeroID),
        _ => matches!(quirk, Quirk::FlowID),
    }
}

/// Quirks are compared as sets, not as ordered lists, and a narrow set of
/// differences is tolerated as a fuzzy match: `df`/`id+` may be absent from
/// the traffic, and `id-`/`ecn` may appear in it. Any other difference
/// rejects the signature outright.
///
/// The fuzzy case is currently reported as the worst non-rejecting score;
/// once the match tiers land it becomes `Fuzzy(QuirksWhitelisted)` instead,
/// which sorts below every exact match regardless of the other fields.
pub(crate) fn distance_quirks(
    observed: &TcpObservation,
    signature: &tcp::Signature,
) -> Option<u32> {
    let declared_by_signature = |quirk: &Quirk| {
        signature.quirks.contains(quirk)
            && !quirk_masked_by_ip_version(quirk, signature.version, observed.version)
    };

    let mut fuzzy = false;

    for quirk in &signature.quirks {
        if quirk_masked_by_ip_version(quirk, signature.version, observed.version)
            || observed.quirks.contains(quirk)
        {
            continue;
        }
        if !FUZZY_DELETABLE_QUIRKS.contains(quirk) {
            return None;
        }
        fuzzy = true;
    }

    for quirk in &observed.quirks {
        if declared_by_signature(quirk) {
            continue;
        }
        if !FUZZY_ADDABLE_QUIRKS.contains(quirk) {
            return None;
        }
        fuzzy = true;
    }

    if fuzzy {
        Some(tcp::TcpMatchQuality::Low.as_score())
    } else {
        Some(tcp::TcpMatchQuality::High.as_score())
    }
}

impl ObservedFingerprint for TcpObservation {
    type Key = TcpIndexKey;

    fn generate_index_key(&self) -> Self::Key {
        let olayout_parts: Vec<String> = self.olayout.iter().map(|opt| format!("{opt}")).collect();
        TcpIndexKey {
            ip_version_key: self.version,
            olayout_key: olayout_parts.join(","),
            pclass_key: self.pclass,
        }
    }
}

impl DatabaseSignature<TcpObservation> for tcp::Signature {
    fn calculate_distance(&self, observed: &TcpObservation) -> Option<u32> {
        let distance = distance_ip_version(&observed.version, &self.version)?
            .saturating_add(distance_ttl(&observed.ittl, &self.ittl)?)
            .saturating_add(distance_olen(observed, self)?)
            .saturating_add(distance_mss(observed, self)?)
            .saturating_add(distance_window_size(&observed.wsize, &self.wsize, observed.mss)?)
            .saturating_add(distance_wscale(observed, self)?)
            .saturating_add(distance_olayout(observed, self)?)
            .saturating_add(distance_quirks(observed, self)?)
            .saturating_add(distance_payload_size(&observed.pclass, &self.pclass)?);
        Some(distance)
    }

    /// Returns the quality score based on the distance.
    ///
    /// The score is a value between 0.0 and 1.0, where 1.0 is a perfect match.
    ///
    /// The score is calculated based on the distance of the observed signal to the database signature.
    /// The distance is a value between 0 and 18, where 0 is a perfect match and 18 is the maximum possible distance.
    ///
    fn get_quality_score(&self, distance: u32) -> f32 {
        tcp::TcpMatchQuality::distance_to_score(distance)
    }

    fn generate_index_keys_for_db_entry(&self) -> Vec<TcpIndexKey> {
        let mut keys = Vec::new();

        let olayout_key_str = self
            .olayout
            .iter()
            .map(|opt| format!("{opt}"))
            .collect::<Vec<String>>()
            .join(",");

        let versions_for_keys = if self.version == IpVersion::Any {
            vec![IpVersion::V4, IpVersion::V6]
        } else {
            vec![self.version]
        };

        let pclasses_for_keys = if self.pclass == PayloadSize::Any {
            vec![PayloadSize::Zero, PayloadSize::NonZero]
        } else {
            vec![self.pclass]
        };

        for v_key_part in &versions_for_keys {
            for pc_key_part in &pclasses_for_keys {
                keys.push(TcpIndexKey {
                    ip_version_key: *v_key_part,
                    olayout_key: olayout_key_str.clone(),
                    pclass_key: *pc_key_part,
                });
            }
        }

        keys
    }
}
