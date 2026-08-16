//! Load-time check for TCP signatures that cover each other.
//!
//! `warn!` when two signatures in a bucket both fit exactly at the same tier.
//! Tests freeze the known list so a new pair in `p0f.fp` fails CI.

use crate::database::{FingerprintCollection, TcpIndexKey};
use crate::db_matching_trait::DatabaseSignature;
use crate::tcp::{IpVersion, PayloadSize, Signature, Ttl, WindowSize};
use huginn_net_tcp::observable::TcpObservation;
use tracing::warn;

type TcpCollection = FingerprintCollection<TcpObservation, Signature, TcpIndexKey>;

/// A pair of signatures in the same bucket that both fit the same observation
/// exactly at the same tier. The first name is the one that would win under
/// p0f's first-match-wins rule (earlier in the `.fp` / index).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AmbiguousExactPair {
    pub section_hint: &'static str,
    pub winner: String,
    pub shadowed: String,
}

/// Build a packet that the signature itself would match exactly, when the
/// signature is concrete enough to pin one down.
fn synthetic_observation(sig: &Signature) -> Option<TcpObservation> {
    let version = match sig.version {
        IpVersion::Any => IpVersion::V4,
        v => v,
    };

    let ittl = match &sig.ittl {
        Ttl::Value(v) | Ttl::Bad(v) | Ttl::Guess(v) => Ttl::Value(*v),
        Ttl::Distance(observed, _) => Ttl::Value(*observed),
    };

    let mss = sig.mss.or(Some(1460));
    let tot_hdr = 40u16;
    let wsize = match &sig.wsize {
        WindowSize::Any => 65535,
        WindowSize::Value(v) => *v,
        WindowSize::Mod(modulus) => {
            if *modulus == 0 {
                return None;
            }
            *modulus
        }
        WindowSize::Mss(multiple) => {
            let m = sig.mss?;
            m.checked_mul(u16::from(*multiple))?
        }
        WindowSize::Mtu(multiple) => {
            // Prefer the `mss + tot_hdr` MTU divisor so `detect_win_multi`
            // recovers `mtu*n` with `of_mtu = true`.
            let m = mss?;
            let mtu = m.checked_add(tot_hdr)?;
            mtu.checked_mul(u16::from(*multiple))?
        }
    };

    let pclass = match sig.pclass {
        PayloadSize::Any => PayloadSize::Zero,
        p => p,
    };

    Some(TcpObservation {
        version,
        ittl,
        olen: sig.olen,
        mss,
        wsize,
        tot_hdr,
        wscale: sig.wscale,
        olayout: sig.olayout.clone(),
        quirks: sig.quirks,
        pclass,
        peer_mss: None,
        tos: 0,
    })
}

fn entry_name(label: &crate::database::Label, sig: &Signature) -> String {
    format!("{label} :: {sig}")
}

/// Ambiguous exact pairs in `collection`, using `section_hint` only for display.
pub fn ambiguous_exact_pairs(
    section_hint: &'static str,
    collection: &TcpCollection,
) -> Vec<AmbiguousExactPair> {
    let mut pairs = Vec::new();

    for (_key, bucket) in collection.index_buckets() {
        for (i, &(li, si)) in bucket.iter().enumerate() {
            let (label_i, sigs_i) = &collection.entries[li];
            let sig_i = &sigs_i[si];
            let Some(obs) = synthetic_observation(sig_i) else {
                continue;
            };
            let Some(fit_i) = sig_i.fit(&obs) else {
                continue;
            };
            if fit_i.fuzzy.is_some() {
                continue;
            }
            // Same-tier only: specific always outranks generic, so mixed pairs
            // are not ambiguous under p0f selection.
            for &(lj, sj) in bucket.iter().skip(i.saturating_add(1)) {
                let (label_j, sigs_j) = &collection.entries[lj];
                let sig_j = &sigs_j[sj];
                if label_j.ty != label_i.ty {
                    continue;
                }
                let Some(fit_j) = sig_j.fit(&obs) else {
                    continue;
                };
                if fit_j.fuzzy.is_some() {
                    continue;
                }
                pairs.push(AmbiguousExactPair {
                    section_hint,
                    winner: entry_name(label_i, sig_i),
                    shadowed: entry_name(label_j, sig_j),
                });
            }
        }
    }

    pairs.sort();
    pairs.dedup();
    pairs
}

/// Emit one `warn!` per ambiguous pair found in the section.
pub fn warn_ambiguous_coverage(section_hint: &'static str, collection: &TcpCollection) {
    for pair in ambiguous_exact_pairs(section_hint, collection) {
        warn!(
            target: "huginn_net_db::coverage",
            "[{}] ambiguous exact signatures (first wins): {}  shadows  {}",
            pair.section_hint, pair.winner, pair.shadowed
        );
    }
}
