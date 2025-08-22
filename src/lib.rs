#![forbid(unsafe_code)]

// ============================================================================
// CORE IMPORTS (database, errors, results - always required)
// ============================================================================
use crate::db::Label;
use crate::fingerprint_result::{FingerprintResult, OSQualityMatched};

pub use crate::db::Database;

// ============================================================================
// TCP PROTOCOL IMPORTS (base protocol)
// ============================================================================
use crate::fingerprint_result::{
    MTUOutput, OperativeSystem, SynAckTCPOutput, SynTCPOutput, UptimeOutput,
};
use crate::uptime::{Connection, SynData};
pub use tcp::Ttl;

// ============================================================================
// HTTP PROTOCOL IMPORTS (depends on TCP)
// ============================================================================
use crate::fingerprint_result::{
    Browser, BrowserQualityMatched, HttpRequestOutput, HttpResponseOutput, WebServer,
    WebServerQualityMatched,
};
use crate::http::{HttpDiagnosis, Signature};
use crate::http_process::{FlowKey, TcpFlow};

// ============================================================================
// TLS PROTOCOL IMPORTS (depends on TCP)
// ============================================================================
use crate::fingerprint_result::TlsClientOutput;

// ============================================================================
// SHARED PROCESSING IMPORTS (used across protocols)
// ============================================================================
use crate::process::ObservablePackage;
use crate::signature_matcher::SignatureMatcher;

// ============================================================================
// OBSERVABLE SIGNALS EXPORTS (conditional in future)
// ============================================================================
pub use observable_signals::{
    ObservableHttpRequest,  // HTTP signals
    ObservableHttpResponse, // HTTP signals
    ObservableTcp,          // TCP signals
    ObservableTlsClient,    // TLS signals
};

// ============================================================================
// EXTERNAL CRATE IMPORTS
// ============================================================================
use pcap_file::pcap::PcapReader;
use pnet::datalink;
use pnet::datalink::Config;
use std::error::Error;
use std::fs::File;
use std::sync::mpsc::Sender;
use tracing::{debug, error};
use ttl_cache::TtlCache;

// ============================================================================
// CORE MODULES (always required - database, matching, errors, results)
// ============================================================================
pub mod db;
pub mod db_matching_trait;
pub mod db_parse;
mod display;
pub mod error;
pub mod fingerprint_result;

// ============================================================================
// TCP PROTOCOL MODULES (base protocol - required by HTTP and TLS)
// ============================================================================
pub mod mtu;
mod observable_tcp_signals_matching;
pub mod tcp;
pub mod tcp_process;
pub mod ttl;
pub mod uptime;
pub mod window_size;

// ============================================================================
// HTTP PROTOCOL MODULES (depends on TCP)
// ============================================================================
pub mod http;
pub mod http_common;
pub mod http1_parser;
pub mod http1_process;
pub mod http2_parser;
pub mod http2_process;
pub mod http_languages;
pub mod http_process;
mod observable_http_signals_matching;

// ============================================================================
// TLS PROTOCOL MODULES (depends on TCP)
// ============================================================================
pub mod tls;
pub mod tls_process;

// ============================================================================
// SHARED PROCESSING MODULES (used by multiple protocols)
// ============================================================================
pub mod ip_options;
pub mod observable_signals;
pub mod process;
pub mod signature_matcher;

/// Configuration for protocol analysis
#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    pub http_enabled: bool,
    pub tcp_enabled: bool,
    pub tls_enabled: bool,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            http_enabled: true,
            tcp_enabled: true,
            tls_enabled: true,
        }
    }
}

/// A multi-protocol passive fingerprinting library inspired by `p0f` with JA4 TLS client fingerprinting.
///
/// The `HuginnNet` struct acts as the core component of the library, handling TCP, HTTP, and TLS packet
/// analysis and matching signatures using a database of known fingerprints, plus JA4 TLS
/// client analysis following the official FoxIO specification.
pub struct HuginnNet<'a> {
    pub matcher: Option<SignatureMatcher<'a>>,
    tcp_cache: TtlCache<Connection, SynData>,
    http_cache: TtlCache<FlowKey, TcpFlow>,
    config: AnalysisConfig,
}

impl<'a> HuginnNet<'a> {
    /// Creates a new instance of `HuginnNet`.
    ///
    /// # Parameters
    /// - `database`: Optional reference to the database containing known TCP/Http signatures from p0f.
    ///   Required if HTTP or TCP analysis is enabled. Not needed for TLS-only analysis.
    /// - `cache_capacity`: The maximum number of connections to maintain in the TTL cache.
    /// - `config`: Optional configuration specifying which protocols to analyze. If None, uses default (all enabled).
    ///
    /// # Returns
    /// A new `HuginnNet` instance initialized with the given database, cache capacity, and configuration.
    pub fn new(
        database: Option<&'a Database>,
        cache_capacity: usize,
        config: Option<AnalysisConfig>,
    ) -> Self {
        let config = config.unwrap_or_default();

        let matcher = if config.tcp_enabled || config.http_enabled {
            database.map(SignatureMatcher::new)
        } else {
            None
        };

        let tcp_cache_size = if config.tcp_enabled {
            cache_capacity
        } else {
            0
        };
        let http_cache_size = if config.http_enabled {
            cache_capacity
        } else {
            0
        };

        Self {
            matcher,
            tcp_cache: TtlCache::new(tcp_cache_size),
            http_cache: TtlCache::new(http_cache_size),
            config,
        }
    }

    fn process_with<F>(
        &mut self,
        mut packet_fn: F,
        sender: Sender<FingerprintResult>,
    ) -> Result<(), Box<dyn Error>>
    where
        F: FnMut() -> Option<Result<Vec<u8>, Box<dyn Error>>>,
    {
        while let Some(packet_result) = packet_fn() {
            match packet_result {
                Ok(packet) => {
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
    ///
    /// # Panics
    /// - If the network interface cannot be found or a channel cannot be created.
    pub fn analyze_network(
        &mut self,
        interface_name: &str,
        sender: Sender<FingerprintResult>,
    ) -> Result<(), Box<dyn Error>> {
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or_else(|| format!("Could not find network interface: {interface_name}"))?;

        debug!("Using network interface: {}", interface.name);

        let config = Config {
            promiscuous: true,
            ..Config::default()
        };

        let (_tx, mut rx) = match datalink::channel(&interface, config) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err("Unhandled channel type".into()),
            Err(e) => return Err(format!("Unable to create channel: {e}").into()),
        };

        self.process_with(
            move || match rx.next() {
                Ok(packet) => Some(Ok(packet.to_vec())),
                Err(e) => Some(Err(e.into())),
            },
            sender,
        )
    }

    /// Analyzes packets from a PCAP file.
    ///
    /// # Parameters
    /// - `pcap_path`: The path to the PCAP file to analyze.
    /// - `sender`: A `Sender` to send `FingerprintResult` objects back to the caller.
    ///
    /// # Panics
    /// - If the PCAP file cannot be opened or read.
    pub fn analyze_pcap(
        &mut self,
        pcap_path: &str,
        sender: Sender<FingerprintResult>,
    ) -> Result<(), Box<dyn Error>> {
        let file = File::open(pcap_path)?;
        let mut pcap_reader = PcapReader::new(file)?;

        self.process_with(
            move || match pcap_reader.next_packet() {
                Some(Ok(packet)) => Some(Ok(packet.data.to_vec())),
                Some(Err(e)) => Some(Err(e.into())),
                None => None,
            },
            sender,
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
            &mut self.tcp_cache,
            &mut self.http_cache,
            &self.config,
        ) {
            Ok(observable_package) => {
                let (syn, syn_ack, mtu, uptime, http_request, http_response, tls_client) = {
                    let mtu: Option<MTUOutput> =
                        observable_package.mtu.and_then(|observable_mtu| {
                            self.matcher.as_ref().and_then(|matcher| {
                                matcher.matching_by_mtu(&observable_mtu.value).map(
                                    |(link, _mtu_result)| MTUOutput {
                                        source: observable_package.source.clone(),
                                        destination: observable_package.destination.clone(),
                                        link: link.clone(),
                                        mtu: observable_mtu.value,
                                    },
                                )
                            })
                        });

                    let syn: Option<SynTCPOutput> =
                        observable_package
                            .tcp_request
                            .map(|observable_tcp| SynTCPOutput {
                                source: observable_package.source.clone(),
                                destination: observable_package.destination.clone(),
                                os_matched: self
                                    .matcher
                                    .as_ref()
                                    .and_then(|matcher| {
                                        matcher.matching_by_tcp_request(&observable_tcp)
                                    })
                                    .map(|(label, _signature, quality)| OSQualityMatched {
                                        os: OperativeSystem::from(label),
                                        quality,
                                    }),
                                sig: observable_tcp,
                            });

                    let syn_ack: Option<SynAckTCPOutput> =
                        observable_package
                            .tcp_response
                            .map(|observable_tcp| SynAckTCPOutput {
                                source: observable_package.source.clone(),
                                destination: observable_package.destination.clone(),
                                os_matched: self
                                    .matcher
                                    .as_ref()
                                    .and_then(|matcher| {
                                        matcher.matching_by_tcp_response(&observable_tcp)
                                    })
                                    .map(|(label, _signature, quality)| OSQualityMatched {
                                        os: OperativeSystem::from(label),
                                        quality,
                                    }),
                                sig: observable_tcp,
                            });

                    let uptime: Option<UptimeOutput> =
                        observable_package.uptime.map(|update| UptimeOutput {
                            source: observable_package.source.clone(),
                            destination: observable_package.destination.clone(),
                            days: update.days,
                            hours: update.hours,
                            min: update.min,
                            up_mod_days: update.up_mod_days,
                            freq: update.freq,
                        });

                    let http_request: Option<HttpRequestOutput> = observable_package
                        .http_request
                        .map(|observable_http_request| {
                            let signature_matcher: Option<(&Label, &Signature, f32)> =
                                self.matcher.as_ref().and_then(|matcher| {
                                    matcher.matching_by_http_request(&observable_http_request)
                                });

                            let ua_matcher: Option<(&String, &Option<String>)> =
                                observable_http_request.user_agent.clone().and_then(|ua| {
                                    self.matcher
                                        .as_ref()
                                        .and_then(|matcher| matcher.matching_by_user_agent(ua))
                                });

                            let http_diagnosis = http_process::get_diagnostic(
                                observable_http_request.user_agent.clone(),
                                ua_matcher,
                                signature_matcher.map(|(label, _signature, _quality)| label),
                            );

                            HttpRequestOutput {
                                source: observable_package.source.clone(),
                                destination: observable_package.destination.clone(),
                                lang: observable_http_request.lang.clone(),
                                browser_matched: signature_matcher.map(
                                    |(label, _signature, quality)| BrowserQualityMatched {
                                        browser: Browser::from(label),
                                        quality,
                                    },
                                ),
                                diagnosis: http_diagnosis,
                                sig: observable_http_request,
                            }
                        });

                    let http_response: Option<HttpResponseOutput> = observable_package
                        .http_response
                        .map(|observable_http_response| HttpResponseOutput {
                            source: observable_package.source.clone(),
                            destination: observable_package.destination.clone(),
                            web_server_matched: self.matcher.as_ref().and_then(|matcher| {
                                matcher
                                    .matching_by_http_response(&observable_http_response)
                                    .map(|(label, _signature, quality)| WebServerQualityMatched {
                                        web_server: WebServer::from(label),
                                        quality,
                                    })
                            }),
                            diagnosis: HttpDiagnosis::None,
                            sig: observable_http_response,
                        });

                    let tls_client: Option<TlsClientOutput> =
                        observable_package
                            .tls_client
                            .map(|observable_tls| TlsClientOutput {
                                source: observable_package.source.clone(),
                                destination: observable_package.destination.clone(),
                                sig: observable_tls,
                            });

                    (
                        syn,
                        syn_ack,
                        mtu,
                        uptime,
                        http_request,
                        http_response,
                        tls_client,
                    )
                };

                FingerprintResult {
                    syn,
                    syn_ack,
                    mtu,
                    uptime,
                    http_request,
                    http_response,
                    tls_client,
                }
            }
            Err(error) => {
                debug!("Fail to process signature: {}", error);
                FingerprintResult {
                    syn: None,
                    syn_ack: None,
                    mtu: None,
                    uptime: None,
                    http_request: None,
                    http_response: None,
                    tls_client: None,
                }
            }
        }
    }
}
