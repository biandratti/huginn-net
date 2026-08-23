//! SYN OS remembered for later HTTP `NAT_APP_UA` checks.
//!
//! Two indexes over the same inserts: `(ip, port)` is flow-exact; `ip` is the
//! p0f-style host fallback. Not the TCP `ConnectionTracker` (uptime / SYN+ACK
//! only). Lives in the umbrella so `huginn-net-http` stays cache-free.

use huginn_net_http::{ObservedOs, ObservedOsScope};
use std::net::IpAddr;
use std::time::Duration;
use ttl_cache::TtlCache;

/// Same window as HTTP flow reassembly: a SYN that is useful for this
/// request is still in the HTTP cache.
const OBSERVED_OS_TTL: Duration = Duration::from_secs(60);

pub struct ObservedOsCache {
    by_flow: TtlCache<(IpAddr, u16), String>,
    by_host: TtlCache<IpAddr, String>,
}

impl ObservedOsCache {
    pub fn new(capacity: usize) -> Self {
        Self { by_flow: TtlCache::new(capacity), by_host: TtlCache::new(capacity) }
    }

    pub fn remember(&mut self, ip: IpAddr, port: u16, name: String) {
        self.by_flow
            .insert((ip, port), name.clone(), OBSERVED_OS_TTL);
        self.by_host.insert(ip, name, OBSERVED_OS_TTL);
    }

    pub fn lookup(&mut self, ip: IpAddr, port: u16) -> Option<ObservedOs> {
        if let Some(name) = self.by_flow.get(&(ip, port)).cloned() {
            return Some(ObservedOs { name, scope: ObservedOsScope::Flow });
        }
        self.by_host
            .get(&ip)
            .cloned()
            .map(|name| ObservedOs { name, scope: ObservedOsScope::Host })
    }
}
