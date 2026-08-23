//! SYN OS remembered for later HTTP `NAT_APP_UA` checks.
//!
//! Key is `(ip, port)` — this connection. No IP-only index. Not the TCP
//! `ConnectionTracker` (uptime / SYN+ACK only). Lives in the umbrella so
//! `huginn-net-http` stays cache-free.

use huginn_net_http::ObservedOs;
use std::net::IpAddr;
use std::time::Duration;
use ttl_cache::TtlCache;

/// Same window as HTTP flow reassembly: a SYN that is useful for this
/// request is still in the HTTP cache.
const OBSERVED_OS_TTL: Duration = Duration::from_secs(60);

pub struct ObservedOsCache {
    by_connection: TtlCache<(IpAddr, u16), String>,
}

impl ObservedOsCache {
    pub fn new(capacity: usize) -> Self {
        Self { by_connection: TtlCache::new(capacity) }
    }

    pub fn remember(&mut self, ip: IpAddr, port: u16, name: String) {
        self.by_connection.insert((ip, port), name, OBSERVED_OS_TTL);
    }

    pub fn lookup(&mut self, ip: IpAddr, port: u16) -> Option<ObservedOs> {
        self.by_connection
            .get(&(ip, port))
            .cloned()
            .map(|name| ObservedOs { name })
    }
}
