#![cfg(feature = "tcp")]
use huginn_net_db::db_matching_trait::{DatabaseSignature, SignatureFit};
use huginn_net_db::tcp::{IpVersion, PayloadSize, Quirk, Signature, Ttl, WindowSize};
use huginn_net_tcp::observable::TcpObservation;
use huginn_net_tcp::output::FuzzyReason;

fn base_observation() -> TcpObservation {
    TcpObservation {
        version: IpVersion::V4,
        ittl: Ttl::Value(64),
        olen: 0,
        mss: Some(1460),
        wsize: 65535,
        tot_hdr: 40,
        wscale: Some(6),
        olayout: Vec::new(),
        quirks: Vec::new(),
        pclass: PayloadSize::Zero,
        peer_mss: None,
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

/// Every field agrees, and the signature's initial TTL is exactly the observed
/// one, so there are no hops to report either.
fn exact() -> Option<SignatureFit<FuzzyReason>> {
    Some(SignatureFit::exact(0))
}

/// The match only holds because these quirks were tolerated, the TTL being
/// plausible.
fn tolerating_quirks(missing: Vec<Quirk>, added: Vec<Quirk>) -> Option<SignatureFit<FuzzyReason>> {
    Some(SignatureFit::fuzzy(
        FuzzyReason {
            implausible_hop_distance: None,
            added_quirks: added,
            missing_quirks: missing,
        },
        0,
    ))
}

#[test]
fn identical_signature_fits_exactly() {
    assert_eq!(base_signature().fit(&base_observation()), exact());
}

#[test]
fn olen_mismatch_rejects_signature() {
    let mut signature = base_signature();
    signature.olen = 4;
    assert_eq!(
        signature.fit(&base_observation()),
        None,
        "olen is never wildcarded in p0f, so a mismatch must reject"
    );
}

#[test]
fn wildcard_mss_matches_any_observed_value() {
    let mut signature = base_signature();
    signature.mss = None;
    assert_eq!(signature.fit(&base_observation()), exact());
}

#[test]
fn mss_mismatch_rejects_signature() {
    let mut signature = base_signature();
    signature.mss = Some(1400);
    assert_eq!(signature.fit(&base_observation()), None, "a concrete mss is a hard gate in p0f");
}

#[test]
fn wildcard_wscale_matches_any_observed_value() {
    let mut signature = base_signature();
    signature.wscale = None;
    assert_eq!(signature.fit(&base_observation()), exact());
}

#[test]
fn wscale_mismatch_rejects_signature() {
    let mut signature = base_signature();
    signature.wscale = Some(7);
    assert_eq!(
        signature.fit(&base_observation()),
        None,
        "a concrete wscale is a hard gate in p0f"
    );
}

#[test]
fn window_size_mismatch_rejects_signature() {
    let mut signature = base_signature();
    signature.wsize = WindowSize::Value(8192);
    assert_eq!(
        signature.fit(&base_observation()),
        None,
        "p0f never tolerates a window size mismatch"
    );
}

#[test]
fn wildcard_window_size_matches_any_observed_value() {
    let mut signature = base_signature();
    signature.wsize = WindowSize::Any;
    assert_eq!(signature.fit(&base_observation()), exact());
}

// ---------------------------------------------------------------------------
// Quirks: set comparison, fuzziness whitelist and IP-version masking.
// ---------------------------------------------------------------------------

#[test]
fn quirks_are_compared_as_sets_not_ordered_lists() {
    let mut signature = base_signature();
    signature.quirks = vec![Quirk::Df, Quirk::NonZeroID];
    let mut observed = base_observation();
    observed.quirks = vec![Quirk::NonZeroID, Quirk::Df];
    assert_eq!(signature.fit(&observed), exact());
}

#[test]
fn missing_df_or_non_zero_id_is_a_fuzzy_match() {
    for quirk in [Quirk::Df, Quirk::NonZeroID] {
        let mut signature = base_signature();
        signature.quirks = vec![quirk.clone()];
        assert_eq!(
            signature.fit(&base_observation()),
            tolerating_quirks(vec![quirk.clone()], vec![]),
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
            base_signature().fit(&observed),
            tolerating_quirks(vec![], vec![quirk.clone()]),
            "p0f tolerates {quirk:?} appearing in the traffic"
        );
    }
}

#[test]
fn other_missing_quirk_rejects_signature() {
    let mut signature = base_signature();
    signature.quirks = vec![Quirk::MustBeZero];
    assert_eq!(signature.fit(&base_observation()), None, "only df and id+ may disappear");
}

#[test]
fn other_extra_quirk_rejects_signature() {
    let mut observed = base_observation();
    observed.quirks = vec![Quirk::SeqNumZero];
    assert_eq!(base_signature().fit(&observed), None, "only id- and ecn may appear");
}

#[test]
fn version_agnostic_signature_ignores_ipv6_only_quirks_on_ipv4() {
    let mut signature = base_signature();
    signature.version = IpVersion::Any;
    signature.quirks = vec![Quirk::FlowID];
    assert_eq!(
        signature.fit(&base_observation()),
        exact(),
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
        signature.fit(&observed),
        exact(),
        "df/id+/id- cannot appear in IPv6 traffic, so they must be masked out"
    );
}

#[test]
fn version_specific_signature_does_not_mask_quirks() {
    let mut signature = base_signature();
    signature.version = IpVersion::V4;
    signature.quirks = vec![Quirk::FlowID];
    assert_eq!(
        signature.fit(&base_observation()),
        None,
        "masking only applies to version-agnostic signatures"
    );
}

#[test]
fn a_decremented_ttl_still_fits_and_reports_the_hops() {
    let mut observed = base_observation();
    observed.ittl = Ttl::Value(59);
    assert_eq!(
        base_signature().fit(&observed),
        Some(SignatureFit::exact(5)),
        "five routers between us and a host with an initial TTL of 64"
    );
}

#[test]
fn an_implausible_hop_count_is_a_fuzzy_match() {
    let mut observed = base_observation();
    observed.ittl = Ttl::Value(10);
    assert_eq!(
        base_signature().fit(&observed),
        Some(SignatureFit::fuzzy(
            FuzzyReason {
                implausible_hop_distance: Some(54),
                added_quirks: vec![],
                missing_quirks: vec![],
            },
            54
        )),
        "54 hops is beyond p0f's MAX_DIST, so the signature only holds as fuzzy"
    );
}

#[test]
fn the_reason_reports_both_tolerances_when_both_apply() {
    let mut signature = base_signature();
    signature.quirks = vec![Quirk::Df];
    let mut observed = base_observation();
    observed.ittl = Ttl::Value(10);
    observed.quirks = vec![Quirk::Ecn];
    assert_eq!(
        signature.fit(&observed),
        Some(SignatureFit::fuzzy(
            FuzzyReason {
                implausible_hop_distance: Some(54),
                added_quirks: vec![Quirk::Ecn],
                missing_quirks: vec![Quirk::Df],
            },
            54
        )),
        "the TTL and the quirks are independent tolerances, so neither hides the other"
    );
}
