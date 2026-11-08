//! Tracks TLS connections in the packet pipeline and turns them into Akamai results.

use super::follow::{FollowHandle, load_file};
use super::session::{SessionLimits, Step, TlsSession};
use super::store::KeyLogStore;
use super::{KeylogConfig, KeylogCounters, KeylogSource, KeylogStats};
use crate::error::HuginnNetHttpError;
use crate::output::{AkamaiOutput, AkamaiTransport, IpPort};
use crate::process::FlowKey;
use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use ttl_cache::TtlCache;

/// How often stalled sessions are re-checked while packets keep flowing.
const SWEEP_INTERVAL: Duration = Duration::from_millis(100);

enum Slot {
    Active(Box<TlsSession>),
    /// Finished or abandoned; kept until its TTL expires so the flow is not tracked again.
    Terminal,
}

/// Decrypts HTTP/2-over-TLS connections with a TLS key log and emits their Akamai fingerprint.
///
/// [`crate::HuginnNetHttp::with_keylog`] sets this up for you. It is public so other
/// analyzers (such as the unified `huginn-net` crate) can drive it from their own packet
/// loop: feed every TCP/IP packet to [`Self::process_ipv4`] / [`Self::process_ipv6`] and call
/// [`Self::sweep_due`] regularly so connections whose secret arrives late still complete.
pub struct KeylogTracker {
    store: Arc<KeyLogStore>,
    counters: Arc<KeylogCounters>,
    limits: SessionLimits,
    sessions: TtlCache<FlowKey, Slot>,
    max_connections: usize,
    session_ttl: Duration,
    last_sweep: Instant,
    follow: Option<Arc<FollowHandle>>,
}

impl KeylogTracker {
    /// Validates the config, loads (or starts following) the key log and creates a tracker
    /// for up to `max_connections` concurrent TLS connections.
    ///
    /// # Errors
    /// [`HuginnNetHttpError::Misconfiguration`] for out-of-range settings and
    /// [`HuginnNetHttpError::Keylog`] when a `File` key log cannot be read or the follower
    /// thread cannot start.
    pub fn new(config: KeylogConfig, max_connections: usize) -> Result<Self, HuginnNetHttpError> {
        config.validate()?;
        let (store, follow) = match &config.source {
            KeylogSource::File(path) => {
                let store = Arc::new(KeyLogStore::new(config.max_entries));
                load_file(path, &store)?;
                (store, None)
            }
            KeylogSource::Follow(path) => {
                let store = Arc::new(KeyLogStore::new(config.max_entries));
                let handle =
                    FollowHandle::spawn(path.clone(), Arc::clone(&store), config.follow_interval)?;
                (store, Some(Arc::new(handle)))
            }
            KeylogSource::Store(store) => (Arc::clone(store), None),
        };
        let limits = SessionLimits {
            pending_timeout: config.pending_timeout,
            max_client_buffer: config.max_client_buffer,
            max_server_buffer: config.max_server_buffer,
        };
        let max_connections = max_connections.max(1);
        Ok(Self {
            store,
            counters: Arc::new(KeylogCounters::default()),
            limits,
            sessions: TtlCache::new(max_connections),
            max_connections,
            session_ttl: config
                .pending_timeout
                .saturating_mul(4)
                .max(Duration::from_secs(60)),
            last_sweep: Instant::now(),
            follow,
        })
    }

    /// A tracker with its own connection table sharing this one's key log store, counters
    /// and follower (one per worker thread in parallel mode).
    #[must_use]
    pub fn for_worker(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            counters: Arc::clone(&self.counters),
            limits: self.limits,
            sessions: TtlCache::new(self.max_connections),
            max_connections: self.max_connections,
            session_ttl: self.session_ttl,
            last_sweep: Instant::now(),
            follow: self.follow.clone(),
        }
    }

    /// Processes one IPv4 packet; returns an Akamai result when a connection completes.
    pub fn process_ipv4(&mut self, packet: &Ipv4Packet) -> Option<AkamaiOutput> {
        if packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
            return None;
        }
        let tcp = TcpPacket::new(packet.payload())?;
        self.process_tcp(
            IpAddr::V4(packet.get_source()),
            IpAddr::V4(packet.get_destination()),
            &tcp,
        )
    }

    /// Processes one IPv6 packet; returns an Akamai result when a connection completes.
    pub fn process_ipv6(&mut self, packet: &Ipv6Packet) -> Option<AkamaiOutput> {
        if packet.get_next_header() != IpNextHeaderProtocols::Tcp {
            return None;
        }
        let tcp = TcpPacket::new(packet.payload())?;
        self.process_tcp(
            IpAddr::V6(packet.get_source()),
            IpAddr::V6(packet.get_destination()),
            &tcp,
        )
    }

    /// Re-checks stalled connections if at least 100 ms passed since the last check.
    pub fn sweep_due(&mut self) -> Vec<AkamaiOutput> {
        if self.last_sweep.elapsed() < SWEEP_INTERVAL {
            return Vec::new();
        }
        self.sweep(false)
    }

    /// Re-checks every stalled connection now. With `force`, connections that still can't
    /// complete are abandoned (use at the end of a capture file).
    pub fn sweep(&mut self, force: bool) -> Vec<AkamaiOutput> {
        let now = Instant::now();
        self.last_sweep = now;
        let mut finished = Vec::new();
        let mut results = Vec::new();
        for (key, slot) in self.sessions.iter_mut() {
            if let Slot::Active(session) = slot {
                let step = session.on_tick(now, &self.store, force);
                if !matches!(step, Step::Pending) {
                    finished.push((*key, step, session.client_random().copied()));
                }
            }
        }
        for (key, step, random) in finished {
            if let Some(out) = self.finish(key, step, random) {
                results.push(out);
            }
        }
        results
    }

    /// Counter snapshot (shared by all trackers created with [`Self::for_worker`]).
    #[must_use]
    pub fn stats(&self) -> KeylogStats {
        self.counters.snapshot(&self.store)
    }

    fn process_tcp(&mut self, src: IpAddr, dst: IpAddr, tcp: &TcpPacket) -> Option<AkamaiOutput> {
        let payload = tcp.payload();
        if payload.is_empty() {
            return None;
        }
        let forward: FlowKey = (src, dst, tcp.get_source(), tcp.get_destination());
        let reverse: FlowKey = (dst, src, tcp.get_destination(), tcp.get_source());
        let now = Instant::now();
        let seq = tcp.get_sequence();

        // One lookup per direction: every lookup hashes the key and reads the clock.
        let (key, step, random) = if let Some(slot) = self.sessions.get_mut(&forward) {
            let (step, random) = drive(slot, true, seq, payload, now, &self.store)?;
            (forward, step, random)
        } else if let Some(slot) = self.sessions.get_mut(&reverse) {
            let (step, random) = drive(slot, false, seq, payload, now, &self.store)?;
            (reverse, step, random)
        } else if is_client_hello_start(payload) {
            let mut session = Box::new(TlsSession::new(self.limits));
            let step = session.on_client_segment(seq, payload, now, &self.store);
            if matches!(step, Step::Pending) {
                self.sessions
                    .insert(forward, Slot::Active(session), self.session_ttl);
                return None;
            }
            (forward, step, session.client_random().copied())
        } else {
            return None;
        };
        self.finish(key, step, random)
    }

    fn finish(
        &mut self,
        key: FlowKey,
        step: Step,
        random: Option<[u8; 32]>,
    ) -> Option<AkamaiOutput> {
        if let Some(random) = random {
            self.store.remove(&random);
        }
        self.sessions.insert(key, Slot::Terminal, self.session_ttl);
        match step {
            Step::Pending => None,
            Step::Abandoned(reason) => {
                self.counters.record(Some(reason));
                None
            }
            Step::Done { fingerprint, version, cipher_suite } => {
                self.counters.record(None);
                Some(AkamaiOutput::new(
                    IpPort::new(key.0, key.2),
                    IpPort::new(key.1, key.3),
                    AkamaiTransport::TlsDecrypted { version, cipher_suite },
                    fingerprint,
                ))
            }
        }
    }
}

impl std::fmt::Debug for KeylogTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeylogTracker")
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

/// Feeds a segment to an active session. `None` while it is pending or already terminal.
fn drive(
    slot: &mut Slot,
    is_client: bool,
    seq: u32,
    payload: &[u8],
    now: Instant,
    store: &KeyLogStore,
) -> Option<(Step, Option<[u8; 32]>)> {
    let Slot::Active(session) = slot else {
        return None;
    };
    let step = if is_client {
        session.on_client_segment(seq, payload, now, store)
    } else {
        session.on_server_segment(seq, payload, now, store)
    };
    if matches!(step, Step::Pending) {
        return None;
    }
    Some((step, session.client_random().copied()))
}

/// A TLS handshake record (`0x16 0x03 ..`) whose first message is a ClientHello (type 1).
fn is_client_hello_start(payload: &[u8]) -> bool {
    matches!(payload, [0x16, 0x03, _, _, _, 0x01, ..])
}
