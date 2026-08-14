#![cfg(feature = "tcp")]
//! Hard-gate behaviour of `Signature::calculate_distance`.
//!
//! p0f rejects a candidate signature outright when `olen`, `mss`, `wscale` or
//! the window size disagree; none of
//! them may degrade into a soft penalty. These tests pin that contract on the
//! public matching API rather than on the `pub(crate)` per-field helpers.

use huginn_net_db::db_matching_trait::DatabaseSignature;
use huginn_net_db::tcp::{
    IpVersion, PayloadSize, Quirk, Signature, TcpMatchQuality, Ttl, WindowSize,
};
use huginn_net_tcp::observable::TcpObservation;

fn base_observation() -> TcpObservation {
    TcpObservation {
        version: IpVersion::V4,
        ittl: Ttl::Value(64),
        olen: 0,
        mss: Some(1460),
        wsize: WindowSize::Value(65535),
        wscale: Some(6),
        olayout: Vec::new(),
        quirks: Vec::new(),
        pclass: PayloadSize::Zero,
    }
}

fn base_signature() -> Signature {
    Signature {
        version: IpVersion::V4,
        ittl: Ttl::Value(64),
        olen: 0,
        mss: Some(1460),
        wsize: WindowSize::Value(65535),
        wscale: Some(6),
        olayout: Vec::new(),
        quirks: Vec::new(),
        pclass: PayloadSize::Zero,
    }
}

#[test]
fn identical_signature_has_zero_distance() {
    assert_eq!(base_signature().calculate_distance(&base_observation()), Some(0));
}

#[test]
fn olen_mismatch_rejects_signature() {
    let mut signature = base_signature();
    signature.olen = 4;
    assert_eq!(
        signature.calculate_distance(&base_observation()),
        None,
        "olen is never wildcarded in p0f, so a mismatch must reject"
    );
}

#[test]
fn wildcard_mss_matches_any_observed_value() {
    let mut signature = base_signature();
    signature.mss = None;
    assert_eq!(signature.calculate_distance(&base_observation()), Some(0));
}

#[test]
fn mss_mismatch_rejects_signature() {
    let mut signature = base_signature();
    signature.mss = Some(1400);
    assert_eq!(
        signature.calculate_distance(&base_observation()),
        None,
        "a concrete mss is a hard gate in p0f"
    );
}

#[test]
fn wildcard_wscale_matches_any_observed_value() {
    let mut signature = base_signature();
    signature.wscale = None;
    assert_eq!(signature.calculate_distance(&base_observation()), Some(0));
}

#[test]
fn wscale_mismatch_rejects_signature() {
    let mut signature = base_signature();
    signature.wscale = Some(7);
    assert_eq!(
        signature.calculate_distance(&base_observation()),
        None,
        "a concrete wscale is a hard gate in p0f"
    );
}

#[test]
fn window_size_mismatch_rejects_signature() {
    let mut signature = base_signature();
    signature.wsize = WindowSize::Value(8192);
    assert_eq!(
        signature.calculate_distance(&base_observation()),
        None,
        "p0f never tolerates a window size mismatch"
    );
}

#[test]
fn wildcard_window_size_matches_any_observed_value() {
    let mut signature = base_signature();
    signature.wsize = WindowSize::Any;
    assert_eq!(signature.calculate_distance(&base_observation()), Some(0));
}

// ---------------------------------------------------------------------------
// Quirks: set comparison, fuzziness whitelist and IP-version masking.
// ---------------------------------------------------------------------------

/// Distance of a quirks-only fuzzy match: every other field is identical, so
/// the whole distance comes from the tolerated quirk difference.
fn fuzzy_quirks_distance() -> Option<u32> {
    Some(TcpMatchQuality::Low.as_score())
}

#[test]
fn quirks_are_compared_as_sets_not_ordered_lists() {
    let mut signature = base_signature();
    signature.quirks = vec![Quirk::Df, Quirk::NonZeroID];
    let mut observed = base_observation();
    observed.quirks = vec![Quirk::NonZeroID, Quirk::Df];
    assert_eq!(signature.calculate_distance(&observed), Some(0));
}

#[test]
fn missing_df_or_non_zero_id_is_a_fuzzy_match() {
    for quirk in [Quirk::Df, Quirk::NonZeroID] {
        let mut signature = base_signature();
        signature.quirks = vec![quirk.clone()];
        assert_eq!(
            signature.calculate_distance(&base_observation()),
            fuzzy_quirks_distance(),
            "p0f tolerates {quirk:?} disappearing from the traffic"
        );
    }
}

#[test]
fn extra_zero_id_or_ecn_is_a_fuzzy_match() {
    for quirk in [Quirk::ZeroID, Quirk::Ecn] {
        let mut observed = base_observation();
        observed.quirks = vec![quirk.clone()];
        assert_eq!(
            base_signature().calculate_distance(&observed),
            fuzzy_quirks_distance(),
            "p0f tolerates {quirk:?} appearing in the traffic"
        );
    }
}

#[test]
fn other_missing_quirk_rejects_signature() {
    let mut signature = base_signature();
    signature.quirks = vec![Quirk::MustBeZero];
    assert_eq!(
        signature.calculate_distance(&base_observation()),
        None,
        "only df and id+ may disappear"
    );
}

#[test]
fn other_extra_quirk_rejects_signature() {
    let mut observed = base_observation();
    observed.quirks = vec![Quirk::SeqNumZero];
    assert_eq!(
        base_signature().calculate_distance(&observed),
        None,
        "only id- and ecn may appear"
    );
}

#[test]
fn version_agnostic_signature_ignores_ipv6_only_quirks_on_ipv4() {
    let mut signature = base_signature();
    signature.version = IpVersion::Any;
    signature.quirks = vec![Quirk::FlowID];
    assert_eq!(
        signature.calculate_distance(&base_observation()),
        Some(0),
        "flow cannot appear in IPv4 traffic, so it must be masked out, not counted as fuzzy"
    );
}

#[test]
fn version_agnostic_signature_ignores_ipv4_only_quirks_on_ipv6() {
    let mut signature = base_signature();
    signature.version = IpVersion::Any;
    signature.quirks = vec![Quirk::Df, Quirk::NonZeroID, Quirk::ZeroID];
    let mut observed = base_observation();
    observed.version = IpVersion::V6;
    assert_eq!(
        signature.calculate_distance(&observed),
        Some(0),
        "df/id+/id- cannot appear in IPv6 traffic, so they must be masked out"
    );
}

#[test]
fn version_specific_signature_does_not_mask_quirks() {
    let mut signature = base_signature();
    signature.version = IpVersion::V4;
    signature.quirks = vec![Quirk::FlowID];
    assert_eq!(
        signature.calculate_distance(&base_observation()),
        None,
        "masking only applies to version-agnostic signatures"
    );
}
