#![cfg(feature = "syn-ack")]

use huginn_net_tcp::process::flow_state::{FlowKey, FlowTracker, SynAckDisposition};
use std::net::{IpAddr, Ipv4Addr};

fn key() -> FlowKey {
    FlowKey::from_syn(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        50000,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        443,
    )
}

fn syn_ack_key() -> FlowKey {
    FlowKey::from_syn_ack(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        443,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        50000,
    )
}

#[test]
fn a_syn_ack_sees_the_mss_recorded_on_the_syn() {
    let mut tracker = FlowTracker::new(16);
    tracker.note_syn(key(), Some(1400));

    assert_eq!(
        tracker.begin_syn_ack(syn_ack_key()),
        SynAckDisposition::First { peer_mss: Some(1400) }
    );
}

#[test]
fn a_second_syn_ack_on_the_same_flow_is_a_duplicate() {
    let mut tracker = FlowTracker::new(16);
    tracker.note_syn(key(), Some(1400));
    let _ = tracker.begin_syn_ack(syn_ack_key());

    assert_eq!(tracker.begin_syn_ack(syn_ack_key()), SynAckDisposition::Duplicate);
}

#[test]
fn a_syn_ack_without_a_prior_syn_still_fingerprints_once() {
    let mut tracker = FlowTracker::new(16);

    assert_eq!(
        tracker.begin_syn_ack(syn_ack_key()),
        SynAckDisposition::First { peer_mss: None }
    );
    assert_eq!(tracker.begin_syn_ack(syn_ack_key()), SynAckDisposition::Duplicate);
}

#[test]
fn a_zero_mss_on_the_syn_is_not_handed_to_the_response() {
    let mut tracker = FlowTracker::new(16);
    tracker.note_syn(key(), Some(0));

    assert_eq!(
        tracker.begin_syn_ack(syn_ack_key()),
        SynAckDisposition::First { peer_mss: None }
    );
}
