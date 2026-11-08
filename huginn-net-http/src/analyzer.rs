use crate::error::HuginnNetHttpError;
use crate::filter::FilterConfig;
use crate::filter::raw as raw_filter;
use crate::http::ObservedOsSource;
use crate::matcher_api::HttpMatcher;
use crate::output::HttpAnalysisResult;
use crate::parser::packet::{IpPacket, parse_packet};
use crate::process::{
    FlowKey, HttpProcessors, PoolStats, SharedHttpMatcher, SharedObservedOsSource, TcpFlow,
    WorkerPool,
};
#[cfg(feature = "akamai-keylog")]
use crate::tls_keylog::{KeylogConfig, KeylogStats, KeylogTracker};
use pcap_file::pcap::PcapReader;
use pnet::datalink::{self, Channel, Config};
use std::fs::File;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use tracing::{debug, error};
use ttl_cache::TtlCache;

#[derive(Debug, Clone)]
struct ParallelConfig {
    num_workers: usize,
    queue_size: usize,
    batch_size: usize,
    timeout_ms: u64,
}

/// An HTTP-focused passive fingerprinting analyzer.
///
/// Extracts HTTP/1.x and HTTP/2 observable signals and optionally matches them
/// against a signature database for browser and web-server identification.
///
/// # Examples
///
/// **Sequential: raw HTTP signals, no database:**
///
/// ```no_run
/// use huginn_net_http::HuginnNetHttp;
/// use std::sync::mpsc;
///
/// let (tx, rx) = mpsc::channel();
/// HuginnNetHttp::new(1000).analyze_pcap("capture.pcap", tx, None).unwrap();
/// for result in rx {
///     if let Some(req) = result.http_request { println!("{req}"); }
/// }
/// ```
///
/// **Sequential with browser/server matching (`huginn-net-db`):**
///
/// ```ignore
/// use huginn_net_http::HuginnNetHttp;
/// use huginn_net_db::{Database, SharedHttpSignatureMatcher};
/// use std::sync::{mpsc, Arc};
///
/// let db = Database::load_default().unwrap();
/// let matcher = Arc::new(SharedHttpSignatureMatcher::from_database(&db));
/// let (tx, rx) = mpsc::channel();
/// HuginnNetHttp::new(1000)
///     .with_matcher(matcher)
///     .analyze_pcap("capture.pcap", tx, None)
///     .unwrap();
/// ```
///
/// **Parallel: flow-based routing so HTTP reassembly state stays per-worker:**
///
/// ```no_run
/// use huginn_net_http::HuginnNetHttp;
/// use std::sync::mpsc;
///
/// let (tx, rx) = mpsc::channel();
/// let mut analyzer = HuginnNetHttp::new(1000).with_parallel(2, 100, 16, 10);
/// // Results are delivered via the sender given to init_pool.
/// analyzer.init_pool(tx.clone()).unwrap();
/// analyzer.analyze_pcap("capture.pcap", tx, None).unwrap();
/// ```
pub struct HuginnNetHttp {
    http_flows: TtlCache<FlowKey, TcpFlow>,
    http_processors: HttpProcessors,
    parallel_config: Option<ParallelConfig>,
    worker_pool: Option<Arc<WorkerPool>>,
    matcher: Option<SharedHttpMatcher>,
    os_source: Option<SharedObservedOsSource>,
    max_connections: usize,
    filter_config: Option<FilterConfig>,
    #[cfg(feature = "akamai-keylog")]
    keylog: Option<KeylogTracker>,
}

impl HuginnNetHttp {
    /// Creates a new instance of `HuginnNetHttp` in sequential mode.
    ///
    /// # Parameters
    /// - `max_connections`: Maximum number of HTTP flows to track
    pub fn new(max_connections: usize) -> Self {
        Self {
            http_flows: TtlCache::new(max_connections),
            http_processors: HttpProcessors::new(),
            parallel_config: None,
            worker_pool: None,
            matcher: None,
            os_source: None,
            max_connections,
            filter_config: None,
            #[cfg(feature = "akamai-keylog")]
            keylog: None,
        }
    }

    /// Enable parallel processing (builder pattern).
    ///
    /// # Parameters
    /// - `num_workers`: Number of worker threads (recommended: 2 for HTTP due to flow tracking)
    /// - `queue_size`: Size of each worker's packet queue (typical: 100-200)
    /// - `batch_size`: Maximum packets to process in one batch (typical: 8-32, recommended: 16)
    /// - `timeout_ms`: Worker receive timeout in milliseconds (typical: 5-20, recommended: 10)
    pub fn with_parallel(
        mut self,
        num_workers: usize,
        queue_size: usize,
        batch_size: usize,
        timeout_ms: u64,
    ) -> Self {
        self.parallel_config =
            Some(ParallelConfig { num_workers, queue_size, batch_size, timeout_ms });
        self
    }

    /// Plug a signature matcher (e.g. `huginn_net_db::SharedHttpSignatureMatcher`).
    ///
    /// Without a matcher, `analyze_*` still returns observable HTTP signals
    /// but every match quality is reported as `Disabled`.
    pub fn with_matcher(mut self, matcher: SharedHttpMatcher) -> Self {
        self.matcher = Some(matcher);
        self
    }

    /// Plug an observed-OS source for UA vs network-OS agreement
    /// (p0f `NAT_APP_UA`).
    ///
    /// Without a source, `analyze_*` still returns HTTP signals and the
    /// `ua_os` field reports [`crate::NotCheckedReason::NoSource`] once the
    /// HTTP-side gates pass.
    pub fn with_observed_os(mut self, os_source: SharedObservedOsSource) -> Self {
        self.os_source = Some(os_source);
        self
    }

    /// Enables Akamai HTTP/2 fingerprinting of HTTP/2-over-TLS connections decrypted with a
    /// TLS key log (NSS `SSLKEYLOGFILE` format).
    ///
    /// With [`crate::KeylogSource::File`] the file is read here, so an unreadable file is
    /// reported now rather than on the packet path. With [`crate::KeylogSource::Follow`] a
    /// background thread keeps reading appended lines until the analyzer is dropped.
    /// Decrypted bytes only feed the Akamai fingerprint; the p0f HTTP outputs are unaffected.
    /// Results arrive in [`HttpAnalysisResult::http_akamai`].
    ///
    /// # Errors
    /// [`HuginnNetHttpError::Misconfiguration`] for out-of-range settings,
    /// [`HuginnNetHttpError::Keylog`] when the key log cannot be read or followed.
    #[cfg(feature = "akamai-keylog")]
    pub fn with_keylog(mut self, config: KeylogConfig) -> Result<Self, HuginnNetHttpError> {
        self.keylog = Some(KeylogTracker::new(config, self.max_connections)?);
        Ok(self)
    }

    /// Key log decryption counters (all zero when [`Self::with_keylog`] was not called).
    /// In parallel mode the counters are shared by all workers.
    #[cfg(feature = "akamai-keylog")]
    #[must_use]
    pub fn keylog_stats(&self) -> KeylogStats {
        self.keylog
            .as_ref()
            .map(KeylogTracker::stats)
            .unwrap_or_default()
    }

    /// Runs one link-layer frame (Ethernet or raw IP) through the sequential pipeline.
    /// Test hook for the key log pipeline; not part of the stable API.
    #[cfg(feature = "akamai-keylog")]
    #[doc(hidden)]
    pub fn analyze_frame(&mut self, frame: &[u8]) -> Option<HttpAnalysisResult> {
        self.process_packet(frame).ok().filter(|r| !r.is_empty())
    }

    /// Re-checks connections waiting for a late key log secret and returns those that
    /// completed. Test hook; the analyze loops call this automatically.
    #[cfg(feature = "akamai-keylog")]
    #[doc(hidden)]
    pub fn sweep_keylog_pending(&mut self) -> Vec<HttpAnalysisResult> {
        self.keylog
            .as_mut()
            .map(|k| k.sweep(false))
            .unwrap_or_default()
            .into_iter()
            .map(crate::process::akamai_only)
            .collect()
    }

    /// Configure packet filtering (builder pattern)
    pub fn with_filter(mut self, config: FilterConfig) -> Self {
        self.filter_config = Some(config);
        self
    }

    /// Initializes the worker pool for parallel processing.
    ///
    /// Must be called after `with_parallel` and before calling `analyze_network` or `analyze_pcap`.
    pub fn init_pool(
        &mut self,
        result_tx: Sender<HttpAnalysisResult>,
    ) -> Result<(), HuginnNetHttpError> {
        if let Some(config) = &self.parallel_config {
            let extras = crate::process::parallel::WorkerExtras {
                #[cfg(feature = "akamai-keylog")]
                keylog: self.keylog.as_ref().map(KeylogTracker::for_worker),
            };
            let pool = WorkerPool::new_with_extras(
                config.num_workers,
                config.queue_size,
                config.batch_size,
                config.timeout_ms,
                result_tx,
                self.matcher.clone(),
                self.os_source.clone(),
                self.max_connections,
                self.filter_config.clone(),
                extras,
            )?;
            self.worker_pool = Some(pool);
            Ok(())
        } else {
            Err(HuginnNetHttpError::Misconfiguration(
                "Parallel config not set. Use with_parallel() to enable parallel processing"
                    .to_string(),
            ))
        }
    }

    /// Returns a reference to the worker pool if initialized.
    pub fn worker_pool(&self) -> Option<Arc<WorkerPool>> {
        self.worker_pool.as_ref().map(Arc::clone)
    }

    /// Returns current worker pool statistics if parallel mode is active.
    pub fn stats(&self) -> Option<PoolStats> {
        self.worker_pool.as_ref().map(|pool| pool.stats())
    }

    fn process_with<F>(
        &mut self,
        packet_fn: F,
        sender: Sender<HttpAnalysisResult>,
        cancel_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), HuginnNetHttpError>
    where
        F: FnMut() -> Option<Result<Vec<u8>, HuginnNetHttpError>>,
    {
        if self.parallel_config.is_some() {
            self.process_parallel(packet_fn, cancel_signal)
        } else {
            self.process_sequential(packet_fn, sender, cancel_signal)
        }
    }

    fn process_sequential<F>(
        &mut self,
        mut packet_fn: F,
        sender: Sender<HttpAnalysisResult>,
        cancel_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), HuginnNetHttpError>
    where
        F: FnMut() -> Option<Result<Vec<u8>, HuginnNetHttpError>>,
    {
        while let Some(packet_result) = packet_fn() {
            if let Some(ref cancel) = cancel_signal {
                if cancel.load(Ordering::Relaxed) {
                    debug!("Cancellation signal received, stopping packet processing");
                    break;
                }
            }

            match packet_result {
                Ok(packet) => match self.process_packet(&packet) {
                    Ok(result) => {
                        if sender.send(result).is_err() {
                            error!("Receiver dropped, stopping packet processing");
                            break;
                        }
                    }
                    Err(http_error) => {
                        debug!("Error processing packet: {}", http_error);
                    }
                },
                Err(e) => {
                    error!("Failed to read packet: {}", e);
                }
            }

            #[cfg(feature = "akamai-keylog")]
            if let Some(keylog) = self.keylog.as_mut() {
                for out in keylog.sweep_due() {
                    if sender.send(crate::process::akamai_only(out)).is_err() {
                        return Ok(());
                    }
                }
            }
        }

        // End of input (or cancelled): connections still waiting for a secret can't complete.
        #[cfg(feature = "akamai-keylog")]
        if let Some(keylog) = self.keylog.as_mut() {
            for out in keylog.sweep(true) {
                if sender.send(crate::process::akamai_only(out)).is_err() {
                    break;
                }
            }
        }
        Ok(())
    }

    fn process_parallel<F>(
        &mut self,
        mut packet_fn: F,
        cancel_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), HuginnNetHttpError>
    where
        F: FnMut() -> Option<Result<Vec<u8>, HuginnNetHttpError>>,
    {
        let worker_pool = self.worker_pool.as_ref().ok_or_else(|| {
            HuginnNetHttpError::Misconfiguration("Worker pool not initialized".to_string())
        })?;

        while let Some(packet_result) = packet_fn() {
            if let Some(ref cancel) = cancel_signal {
                if cancel.load(Ordering::Relaxed) {
                    debug!("Cancellation signal received, stopping packet processing");
                    break;
                }
            }

            match packet_result {
                Ok(packet) => {
                    let _ = worker_pool.dispatch(packet);
                }
                Err(e) => {
                    error!("Failed to read packet: {}", e);
                }
            }
        }

        worker_pool.shutdown();
        Ok(())
    }

    /// Analyzes network traffic from a live network interface for HTTP packets.
    pub fn analyze_network(
        &mut self,
        interface_name: &str,
        sender: Sender<HttpAnalysisResult>,
        cancel_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), HuginnNetHttpError> {
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or_else(|| {
                HuginnNetHttpError::Parse(format!(
                    "Could not find network interface: {interface_name}"
                ))
            })?;

        debug!("Using network interface: {}", interface.name);

        let config = Config { promiscuous: true, ..Config::default() };

        let (_tx, mut rx) = match datalink::channel(&interface, config) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(HuginnNetHttpError::Parse("Unhandled channel type".to_string())),
            Err(e) => {
                return Err(HuginnNetHttpError::Parse(format!("Unable to create channel: {e}")));
            }
        };

        self.process_with(
            move || match rx.next() {
                Ok(packet) => Some(Ok(packet.to_vec())),
                Err(e) => {
                    Some(Err(HuginnNetHttpError::Parse(format!("Error receiving packet: {e}"))))
                }
            },
            sender,
            cancel_signal,
        )
    }

    /// Analyzes HTTP packets from a PCAP file.
    pub fn analyze_pcap(
        &mut self,
        pcap_path: &str,
        sender: Sender<HttpAnalysisResult>,
        cancel_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), HuginnNetHttpError> {
        let file = File::open(pcap_path)
            .map_err(|e| HuginnNetHttpError::Parse(format!("Failed to open PCAP file: {e}")))?;
        let mut pcap_reader = PcapReader::new(file)
            .map_err(|e| HuginnNetHttpError::Parse(format!("Failed to create PCAP reader: {e}")))?;

        self.process_with(
            move || match pcap_reader.next_packet() {
                Some(Ok(packet)) => Some(Ok(packet.data.to_vec())),
                Some(Err(e)) => {
                    Some(Err(HuginnNetHttpError::Parse(format!("Error reading PCAP packet: {e}"))))
                }
                None => None,
            },
            sender,
            cancel_signal,
        )
    }

    /// Processes a single packet and extracts HTTP information if present.
    fn process_packet(&mut self, packet: &[u8]) -> Result<HttpAnalysisResult, HuginnNetHttpError> {
        if let Some(ref filter) = self.filter_config {
            if !raw_filter::apply(packet, filter) {
                debug!("Filtered out packet before parsing");
                return Ok(HttpAnalysisResult::empty());
            }
        }

        let matcher: Option<&dyn HttpMatcher> =
            self.matcher.as_deref().map(|m| m as &dyn HttpMatcher);
        let os_source: Option<&dyn ObservedOsSource> = self
            .os_source
            .as_deref()
            .map(|s| s as &dyn ObservedOsSource);

        match parse_packet(packet) {
            IpPacket::Ipv4(ipv4) => {
                #[cfg(feature = "akamai-keylog")]
                let akamai = self.keylog.as_mut().and_then(|k| k.process_ipv4(&ipv4));
                let result = crate::process::process_ipv4_packet(
                    &ipv4,
                    &mut self.http_flows,
                    &self.http_processors,
                    matcher,
                    os_source,
                );
                #[cfg(feature = "akamai-keylog")]
                let result = crate::process::merge_keylog_akamai(result, akamai);
                result
            }
            IpPacket::Ipv6(ipv6) => {
                #[cfg(feature = "akamai-keylog")]
                let akamai = self.keylog.as_mut().and_then(|k| k.process_ipv6(&ipv6));
                let result = crate::process::process_ipv6_packet(
                    &ipv6,
                    &mut self.http_flows,
                    &self.http_processors,
                    matcher,
                    os_source,
                );
                #[cfg(feature = "akamai-keylog")]
                let result = crate::process::merge_keylog_akamai(result, akamai);
                result
            }
            IpPacket::None => Ok(HttpAnalysisResult::empty()),
        }
    }
}
