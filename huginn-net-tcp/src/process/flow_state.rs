//! Per-flow state the SYN+ACK fingerprint needs from the SYN.
//!
//! p0f keeps `f->syn_mss` and `f->acked` on the flow (`process.c` /
//! `fp_tcp.c`). The peer MSS is the last window divisor tried on a response,
//! and `acked` stops a repeated SYN+ACK from being fingerprinted twice.

use std::net::IpAddr;
use std::time::Duration;
use ttl_cache::TtlCache;

/// How long a handshake's flow state is kept after the last update.
const FLOW_CACHE_TTL_SECS: u64 = 30;

/// Canonical client→server key for a TCP handshake.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub(crate) struct FlowKey {
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub server_ip: IpAddr,
    pub server_port: u16,
}

impl FlowKey {
    pub fn from_syn(
        client_ip: IpAddr,
        client_port: u16,
        server_ip: IpAddr,
        server_port: u16,
    ) -> Self {
        Self { client_ip, client_port, server_ip, server_port }
    }

    /// SYN+ACK is server→client; flip it back to the SYN's orientation.
    pub fn from_syn_ack(
        server_ip: IpAddr,
        server_port: u16,
        client_ip: IpAddr,
        client_port: u16,
    ) -> Self {
        Self { client_ip, client_port, server_ip, server_port }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct FlowState {
    /// MSS advertised on the client's SYN, when the option was present.
    pub syn_mss: Option<u16>,
    /// A fingerprinted SYN+ACK has already been seen for this flow.
    pub acked: bool,
}

/// What to do with a SYN+ACK once flow state has been consulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SynAckDisposition {
    /// A previous SYN+ACK of this flow was already fingerprinted.
    Duplicate,
    /// First SYN+ACK; carry the peer MSS the window divisors may need.
    First { peer_mss: Option<u16> },
}

pub(crate) struct FlowTracker {
    cache: TtlCache<FlowKey, FlowState>,
}

impl FlowTracker {
    pub fn new(max_connections: usize) -> Self {
        Self { cache: TtlCache::new(max_connections) }
    }

    /// Record the client's MSS from a SYN. Resets `acked` so a new handshake
    /// on the same 4-tuple can be fingerprinted again.
    pub fn note_syn(&mut self, key: FlowKey, syn_mss: Option<u16>) {
        self.cache.insert(
            key,
            FlowState { syn_mss, acked: false },
            Duration::new(FLOW_CACHE_TTL_SECS, 0),
        );
    }

    /// Consume a SYN+ACK against the flow: either reject it as a duplicate or
    /// mark the flow acked and hand back the peer MSS.
    pub fn begin_syn_ack(&mut self, key: FlowKey) -> SynAckDisposition {
        let state = self.cache.get(&key).copied();
        match state {
            Some(FlowState { acked: true, .. }) => SynAckDisposition::Duplicate,
            Some(FlowState { syn_mss, .. }) => {
                self.cache.insert(
                    key,
                    FlowState { syn_mss, acked: true },
                    Duration::new(FLOW_CACHE_TTL_SECS, 0),
                );
                SynAckDisposition::First { peer_mss: syn_mss.filter(|&m| m != 0) }
            }
            None => {
                // No SYN seen; still fingerprint once, without a peer MSS.
                self.cache.insert(
                    key,
                    FlowState { syn_mss: None, acked: true },
                    Duration::new(FLOW_CACHE_TTL_SECS, 0),
                );
                SynAckDisposition::First { peer_mss: None }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
