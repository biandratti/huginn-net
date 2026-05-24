mod matchers;
use matchers::cache_sizes;
#[cfg(feature = "http-p0f-request")]
use matchers::HttpRequestMatchResult;

use crate::error::HuginnNetError;
use crate::output::FingerprintResult;
use crate::process::ObservablePackage;
#[cfg(feature = "http-p0f-response")]
use huginn_net_http::http::HttpDiagnosis;
use huginn_net_http::http_process::{FlowKey, HttpProcessors, TcpFlow};
#[cfg(feature = "http-p0f-request")]
use huginn_net_http::output::HttpRequestOutput;
#[cfg(feature = "http-p0f-response")]
use huginn_net_http::output::HttpResponseOutput;
#[cfg(feature = "tcp-mtu")]
use huginn_net_tcp::output::MTUOutput;
#[cfg(feature = "tcp-syn-ack")]
use huginn_net_tcp::output::SynAckTCPOutput;
#[cfg(feature = "tcp-syn")]
use huginn_net_tcp::output::SynTCPOutput;
#[cfg(feature = "tcp-uptime")]
use huginn_net_tcp::output::{UptimeOutput, UptimeRole};
use huginn_net_tcp::ConnectionTracker;
use huginn_net_tls::output::TlsClientOutput;
use pcap_file::pcap::PcapReader;
use pnet::datalink::{self, Channel, Config};
use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use tracing::{debug, error};
use ttl_cache::TtlCache;

#[cfg(feature = "db")]
use huginn_net_db::Database;

#[cfg(feature = "http-p0f-request")]
pub use huginn_net_http::observable::ObservableHttpRequest;
#[cfg(feature = "http-p0f-response")]
pub use huginn_net_http::observable::ObservableHttpResponse;
pub use huginn_net_tcp::observable::ObservableTcp;
use huginn_net_tcp::FilterConfig;
pub use huginn_net_tls::ObservableTlsClient;

/// Configuration for protocol analysis
#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    /// Enable HTTP protocol analysis
    pub http_enabled: bool,
    /// Enable TCP protocol analysis
    pub tcp_enabled: bool,
    /// Enable TLS protocol analysis
    pub tls_enabled: bool,
    /// Enable fingerprint matching against the database. When false, all quality matched results will be Disabled.
    pub matcher_enabled: bool,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self { http_enabled: true, tcp_enabled: true, tls_enabled: true, matcher_enabled: true }
    }
}

/// A multi-protocol passive fingerprinting analyzer: TCP (p0f-style), HTTP, and TLS (JA4).
///
/// Combines all three protocols in a single sequential pass over each packet,
/// producing a unified [`FingerprintResult`] per packet. For single-protocol
/// high-throughput use cases, prefer the individual crates
/// (`huginn-net-tcp`, `huginn-net-http`, `huginn-net-tls`) which support
/// parallel worker pools.
///
/// # Examples
///
/// **With p0f database, TCP + HTTP matching enabled (requires `db` feature):**
///
/// ```no_run
/// # #[cfg(all(feature = "db", feature = "tcp-syn", feature = "http-p0f-request"))] {
/// use huginn_net::{Database, HuginnNet};
/// use std::sync::mpsc;
///
/// let db = Database::load_default().unwrap();
/// let (tx, rx) = mpsc::channel();
/// HuginnNet::new(Some(&db), 1000, None)
///     .unwrap()
///     .analyze_pcap("capture.pcap", tx, None)
///     .unwrap();
/// for result in rx {
///     if let Some(syn) = result.tcp_syn   { println!("{syn}"); }
///     if let Some(req) = result.http_request { println!("{req}"); }
///     if let Some(tls) = result.tls_client  { println!("{tls}"); }
/// }
/// # }
/// ```
///
/// **Observation-only, no database, all protocols, matching disabled:**
///
/// ```no_run
/// # #[cfg(feature = "db")] {
/// use huginn_net::{AnalysisConfig, HuginnNet};
/// use std::sync::mpsc;
///
/// let config = AnalysisConfig { matcher_enabled: false, ..Default::default() };
/// let (tx, rx) = mpsc::channel();
/// HuginnNet::new(None, 1000, Some(config))
///     .unwrap()
///     .analyze_pcap("capture.pcap", tx, None)
///     .unwrap();
/// # }
/// ```
pub struct HuginnNet<'a> {
    #[cfg(feature = "db")]
    pub tcp_matcher: Option<huginn_net_db::TcpSignatureMatcher<'a>>,
    #[cfg(feature = "db")]
    pub http_matcher: Option<huginn_net_db::HttpSignatureMatcher<'a>>,
    connection_tracker: ConnectionTracker,
    http_flows: TtlCache<FlowKey, TcpFlow>,
    http_processors: HttpProcessors,
    pub(crate) config: AnalysisConfig,
    filter_config: Option<FilterConfig>,
    #[cfg(not(feature = "db"))]
    _lifetime: std::marker::PhantomData<&'a ()>,
}

impl<'a> HuginnNet<'a> {
    /// Creates a new instance of `HuginnNet` with database-backed matchers.
    ///
    /// # Parameters
    /// - `database`: Optional reference to the database containing known TCP/Http signatures from p0f.
    ///   Only loaded if `matcher_enabled` is true and HTTP or TCP analysis is enabled.
    ///   Not needed for TLS-only analysis or when fingerprint matching is disabled.
    /// - `max_connections`: The maximum number of connections to maintain in the connection tracker and HTTP flows.
    /// - `config`: Optional configuration specifying which protocols to analyze. If None, uses default (all enabled).
    ///   When `matcher_enabled` is false, the database won't be loaded and no signature matching will be performed.
    ///
    /// # Returns
    /// A new `HuginnNet` instance initialized with the given database, max connections, and configuration.
    ///
    /// # Errors
    /// Returns `HuginnNetError::MissConfiguration` if `matcher_enabled` is true but no database is provided.
    ///
    /// Available only with the `db` feature (enabled by default). Without
    /// `db`, use `HuginnNet::new_observable` for an observation-only
    /// analyzer (no p0f matching).
    #[cfg(feature = "db")]
    pub fn new(
        database: Option<&'a Database>,
        max_connections: usize,
        config: Option<AnalysisConfig>,
    ) -> Result<Self, HuginnNetError> {
        let config = config.unwrap_or_default();

        if config.matcher_enabled
            && (config.tcp_enabled || config.http_enabled)
            && database.is_none()
        {
            return Err(HuginnNetError::MissConfiguration(
                "Database is required when matcher is enabled".to_string(),
            ));
        }

        let tcp_matcher = if config.matcher_enabled && config.tcp_enabled {
            database.map(|db| huginn_net_db::TcpSignatureMatcher::new(&db.tcp))
        } else {
            None
        };

        let http_matcher = if config.matcher_enabled && config.http_enabled {
            database.map(|db| huginn_net_db::HttpSignatureMatcher::new(&db.http))
        } else {
            None
        };

        let (connection_tracker_size, http_flows_size) = cache_sizes(&config, max_connections);

        Ok(Self {
            tcp_matcher,
            http_matcher,
            connection_tracker: ConnectionTracker::new(connection_tracker_size),
            http_flows: TtlCache::new(http_flows_size),
            http_processors: HttpProcessors::new(),
            config,
            filter_config: None,
        })
    }

    /// Creates a new instance of `HuginnNet` without any p0f signature matcher.
    ///
    /// All TCP/HTTP outputs will report `MatchQuality::Disabled` for fingerprint
    /// matching, but raw observations (TCP/HTTP signatures, TLS JA4 fingerprints,
    /// uptime, MTU values, etc.) are still produced.
    ///
    /// Use this when you want to bring your own matcher implementation, or when
    /// only TLS / observation-level data is needed.
    ///
    /// Available only without the `db` feature. With `db`, use
    /// [`HuginnNet::new`] and pass `None` as the database to disable matching.
    #[cfg(not(feature = "db"))]
    pub fn new_observable(
        max_connections: usize,
        config: Option<AnalysisConfig>,
    ) -> Result<Self, HuginnNetError> {
        let config = config.unwrap_or_default();
        let (connection_tracker_size, http_flows_size) = cache_sizes(&config, max_connections);

        Ok(Self {
            connection_tracker: ConnectionTracker::new(connection_tracker_size),
            http_flows: TtlCache::new(http_flows_size),
            http_processors: HttpProcessors::new(),
            config,
            filter_config: None,
            _lifetime: std::marker::PhantomData,
        })
    }

    /// Configure packet filtering for this analyzer.
    ///
    /// Filters packets by IP address and/or port before processing.
    /// This is more efficient than processing all packets and filtering later.
    ///
    /// # Parameters
    /// - `filter`: The `FilterConfig` to apply to incoming packets.
    ///
    /// # Returns
    /// A new `HuginnNet` instance with the filter configured.
    pub fn with_filter(mut self, filter: FilterConfig) -> Self {
        self.filter_config = Some(filter);
        self
    }

    fn process_with<F>(
        &mut self,
        mut packet_fn: F,
        sender: Sender<FingerprintResult>,
        cancel_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), HuginnNetError>
    where
        F: FnMut() -> Option<Result<Vec<u8>, HuginnNetError>>,
    {
        while let Some(packet_result) = packet_fn() {
            if let Some(ref cancel) = cancel_signal {
                if cancel.load(Ordering::Relaxed) {
                    debug!("Cancellation signal received, stopping packet processing");
                    break;
                }
            }

            match packet_result {
                Ok(packet) => {
                    if let Some(ref filter) = self.filter_config {
                        if !huginn_net_tcp::raw_filter::apply(&packet, filter) {
                            debug!("Filtered out packet before parsing");
                            continue;
                        }
                    }

                    let output = self.analyze_tcp(&packet);
                    if sender.send(output).is_err() {
                        error!("Receiver dropped, stopping packet processing");
                        break;
                    }
                }
                Err(e) => {
                    error!("Failed to read packet: {}", e);
                }
            }
        }
        Ok(())
    }

    /// Captures and analyzes packets on the specified network interface.
    ///
    /// Sends `FingerprintResult` through the provided channel.
    ///
    /// # Parameters
    /// - `interface_name`: The name of the network interface to analyze.
    /// - `sender`: A `Sender` to send `FingerprintResult` objects back to the caller.
    /// - `cancel_signal`: Optional `Arc<AtomicBool>` to signal graceful shutdown.
    ///
    /// # Errors
    /// - If the network interface cannot be found or a channel cannot be created.
    pub fn analyze_network(
        &mut self,
        interface_name: &str,
        sender: Sender<FingerprintResult>,
        cancel_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), HuginnNetError> {
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or_else(|| {
                HuginnNetError::MissConfiguration(format!(
                    "Could not find network interface: {interface_name}"
                ))
            })?;

        debug!("Using network interface: {}", interface.name);

        let config = Config { promiscuous: true, ..Config::default() };

        let (_tx, mut rx) = match datalink::channel(&interface, config) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                return Err(HuginnNetError::MissConfiguration("Unhandled channel type".to_string()))
            }
            Err(e) => {
                return Err(HuginnNetError::MissConfiguration(format!(
                    "Unable to create channel: {e}"
                )))
            }
        };

        self.process_with(
            move || match rx.next() {
                Ok(packet) => Some(Ok(packet.to_vec())),
                Err(e) => Some(Err(HuginnNetError::MissConfiguration(format!(
                    "Error receiving packet: {e}"
                )))),
            },
            sender,
            cancel_signal,
        )
    }

    /// Analyzes packets from a PCAP file.
    ///
    /// # Parameters
    /// - `pcap_path`: The path to the PCAP file to analyze.
    /// - `sender`: A `Sender` to send `FingerprintResult` objects back to the caller.
    /// - `cancel_signal`: Optional `Arc<AtomicBool>` to signal graceful shutdown.
    ///
    /// # Errors
    /// - If the PCAP file cannot be opened or read.
    pub fn analyze_pcap(
        &mut self,
        pcap_path: &str,
        sender: Sender<FingerprintResult>,
        cancel_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), HuginnNetError> {
        let file = File::open(pcap_path).map_err(|e| {
            HuginnNetError::MissConfiguration(format!("Failed to open PCAP file: {e}"))
        })?;
        let mut pcap_reader = PcapReader::new(file).map_err(|e| {
            HuginnNetError::MissConfiguration(format!("Failed to create PCAP reader: {e}"))
        })?;

        self.process_with(
            move || match pcap_reader.next_packet() {
                Some(Ok(packet)) => Some(Ok(packet.data.to_vec())),
                Some(Err(e)) => Some(Err(HuginnNetError::MissConfiguration(format!(
                    "Error reading PCAP packet: {e}"
                )))),
                None => None,
            },
            sender,
            cancel_signal,
        )
    }

    /// Analyzes a TCP packet and returns a `FingerprintResult` object.
    ///
    /// # Parameters
    /// - `packet`: A reference to the TCP packet to analyze.
    ///
    /// # Returns
    /// A `FingerprintResult` object containing the analysis results.
    pub fn analyze_tcp(&mut self, packet: &[u8]) -> FingerprintResult {
        match ObservablePackage::extract(
            packet,
            &mut self.connection_tracker,
            &mut self.http_flows,
            &self.http_processors,
            &self.config,
        ) {
            Ok(observable_package) => {
                #[cfg(feature = "tcp-mtu")]
                let mtu: Option<MTUOutput> = observable_package.mtu.map(|observable_mtu| {
                    let link_quality = self.match_mtu(&observable_mtu.value);

                    MTUOutput {
                        source: huginn_net_tcp::output::IpPort::new(
                            observable_package.source.ip,
                            observable_package.source.port,
                        ),
                        destination: huginn_net_tcp::output::IpPort::new(
                            observable_package.destination.ip,
                            observable_package.destination.port,
                        ),
                        link: link_quality,
                        mtu: observable_mtu.value,
                    }
                });

                #[cfg(feature = "tcp-syn")]
                let syn: Option<SynTCPOutput> =
                    observable_package.tcp_request.map(|observable_tcp| {
                        let os_quality = self.match_tcp_request(&observable_tcp);

                        SynTCPOutput {
                            source: huginn_net_tcp::output::IpPort::new(
                                observable_package.source.ip,
                                observable_package.source.port,
                            ),
                            destination: huginn_net_tcp::output::IpPort::new(
                                observable_package.destination.ip,
                                observable_package.destination.port,
                            ),
                            os_matched: os_quality,
                            sig: observable_tcp,
                        }
                    });

                #[cfg(feature = "tcp-syn-ack")]
                let syn_ack: Option<SynAckTCPOutput> =
                    observable_package.tcp_response.map(|observable_tcp| {
                        let os_quality = self.match_tcp_response(&observable_tcp);

                        SynAckTCPOutput {
                            source: huginn_net_tcp::output::IpPort::new(
                                observable_package.source.ip,
                                observable_package.source.port,
                            ),
                            destination: huginn_net_tcp::output::IpPort::new(
                                observable_package.destination.ip,
                                observable_package.destination.port,
                            ),
                            os_matched: os_quality,
                            sig: observable_tcp,
                        }
                    });

                #[cfg(feature = "tcp-uptime")]
                let client_uptime: Option<UptimeOutput> =
                    observable_package.client_uptime.map(|update| UptimeOutput {
                        source: huginn_net_tcp::output::IpPort::new(
                            observable_package.source.ip,
                            observable_package.source.port,
                        ),
                        destination: huginn_net_tcp::output::IpPort::new(
                            observable_package.destination.ip,
                            observable_package.destination.port,
                        ),
                        role: UptimeRole::Client,
                        days: update.days,
                        hours: update.hours,
                        min: update.min,
                        up_mod_days: update.up_mod_days,
                        freq: update.freq,
                    });

                #[cfg(feature = "tcp-uptime")]
                let server_uptime: Option<UptimeOutput> =
                    observable_package.server_uptime.map(|update| UptimeOutput {
                        source: huginn_net_tcp::output::IpPort::new(
                            observable_package.source.ip,
                            observable_package.source.port,
                        ),
                        destination: huginn_net_tcp::output::IpPort::new(
                            observable_package.destination.ip,
                            observable_package.destination.port,
                        ),
                        role: UptimeRole::Server,
                        days: update.days,
                        hours: update.hours,
                        min: update.min,
                        up_mod_days: update.up_mod_days,
                        freq: update.freq,
                    });

                #[cfg(feature = "http-p0f-request")]
                let http_request: Option<HttpRequestOutput> =
                    observable_package
                        .http_request
                        .map(|observable_http_request| {
                            let HttpRequestMatchResult { browser_quality, http_diagnosis } =
                                self.match_http_request(&observable_http_request);

                            HttpRequestOutput {
                                source: huginn_net_http::output::IpPort::new(
                                    observable_package.source.ip,
                                    observable_package.source.port,
                                ),
                                destination: huginn_net_http::output::IpPort::new(
                                    observable_package.destination.ip,
                                    observable_package.destination.port,
                                ),
                                lang: observable_http_request.lang.clone(),
                                browser_matched: browser_quality,
                                diagnosis: http_diagnosis,
                                sig: observable_http_request,
                            }
                        });

                #[cfg(feature = "http-p0f-response")]
                let http_response: Option<HttpResponseOutput> = observable_package
                    .http_response
                    .map(|observable_http_response| {
                        let web_server_quality =
                            self.match_http_response(&observable_http_response);

                        HttpResponseOutput {
                            source: huginn_net_http::output::IpPort::new(
                                observable_package.source.ip,
                                observable_package.source.port,
                            ),
                            destination: huginn_net_http::output::IpPort::new(
                                observable_package.destination.ip,
                                observable_package.destination.port,
                            ),
                            web_server_matched: web_server_quality,
                            diagnosis: HttpDiagnosis::None,
                            sig: observable_http_response,
                        }
                    });

                let tls_client: Option<TlsClientOutput> =
                    observable_package
                        .tls_client
                        .map(|observable_tls| TlsClientOutput {
                            source: huginn_net_tls::output::IpPort::new(
                                observable_package.source.ip,
                                observable_package.source.port,
                            ),
                            destination: huginn_net_tls::output::IpPort::new(
                                observable_package.destination.ip,
                                observable_package.destination.port,
                            ),
                            sig: observable_tls,
                        });

                FingerprintResult {
                    #[cfg(feature = "tcp-syn")]
                    tcp_syn: syn,
                    #[cfg(feature = "tcp-syn-ack")]
                    tcp_syn_ack: syn_ack,
                    #[cfg(feature = "tcp-mtu")]
                    tcp_mtu: mtu,
                    #[cfg(feature = "tcp-uptime")]
                    tcp_client_uptime: client_uptime,
                    #[cfg(feature = "tcp-uptime")]
                    tcp_server_uptime: server_uptime,
                    #[cfg(feature = "http-p0f-request")]
                    http_request,
                    #[cfg(feature = "http-p0f-response")]
                    http_response,
                    tls_client,
                }
            }
            Err(error) => {
                debug!("Fail to process signature: {}", error);
                FingerprintResult {
                    #[cfg(feature = "tcp-syn")]
                    tcp_syn: None,
                    #[cfg(feature = "tcp-syn-ack")]
                    tcp_syn_ack: None,
                    #[cfg(feature = "tcp-mtu")]
                    tcp_mtu: None,
                    #[cfg(feature = "tcp-uptime")]
                    tcp_client_uptime: None,
                    #[cfg(feature = "tcp-uptime")]
                    tcp_server_uptime: None,
                    #[cfg(feature = "http-p0f-request")]
                    http_request: None,
                    #[cfg(feature = "http-p0f-response")]
                    http_response: None,
                    tls_client: None,
                }
            }
        }
    }
}
