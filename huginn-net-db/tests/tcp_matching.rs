#![cfg(feature = "tcp")]
//! Hard-gate behaviour of `Signature::calculate_distance`.
//!
//! p0f rejects a candidate signature outright when `olen`, `mss`, `wscale` or
//! the window size disagree (`data/p0f/fp_tcp.c::tcp_find_match`); none of
//! them may degrade into a soft penalty. These tests pin that contract on the
//! public matching API rather than on the `pub(crate)` per-field helpers.

use huginn_net_db::db_matching_trait::DatabaseSignature;
use huginn_net_db::tcp::{IpVersion, PayloadSize, Signature, Ttl, WindowSize};
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
