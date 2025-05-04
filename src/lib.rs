pub mod db;
mod db_parse;
mod display;
mod http;
mod http_languages;
mod http_process;
mod ip_options;
mod mtu;
pub mod p0f_output;
mod process;
mod signature_matcher;
pub mod tcp;
mod tcp_process;
pub mod ttl;
mod uptime;
pub mod window_size;

use crate::db::{Database, Label};
use crate::http::{HttpDiagnosis, Signature};
use crate::http_process::{FlowKey, TcpFlow};
use crate::p0f_output::{
    HttpRequestOutput, HttpResponseOutput, MTUOutput, OSQualityMatched, OperativeSystem, P0fOutput,
    SynAckTCPOutput, SynTCPOutput, UptimeOutput,
};
use crate::process::ObservablePackage;
use crate::signature_matcher::SignatureMatcher;
use crate::uptime::{Connection, SynData};
use log::{debug, error};
use p0f_output::MatchedLabel;
use pnet::datalink;
use pnet::datalink::Config;
use std::sync::mpsc::Sender;
pub use tcp::Ttl;
use ttl_cache::TtlCache;

pub struct P0f<'a> {
    pub matcher: SignatureMatcher<'a>,
    tcp_cache: TtlCache<Connection, SynData>,
    http_cache: TtlCache<FlowKey, TcpFlow>,
}

/// A passive TCP fingerprinting engine inspired by `p0f`.
///
/// The `P0f` struct acts as the core component of the library, handling TCP packet
/// analysis and matching signatures using a database of known fingerprints.
impl<'a> P0f<'a> {
    /// Creates a new instance of `P0f`.
    ///
    /// # Parameters
    /// - `database`: A reference to the database containing known TCP/IP signatures.
    /// - `cache_capacity`: The maximum number of connections to maintain in the TTL cache.
    ///
    /// # Returns
    /// A new `P0f` instance initialized with the given database and cache capacity.
    pub fn new(database: &'a Database, cache_capacity: usize) -> Self {
        let matcher: SignatureMatcher = SignatureMatcher::new(database);
        let tcp_cache: TtlCache<Connection, SynData> = TtlCache::new(cache_capacity);
        let http_cache: TtlCache<FlowKey, TcpFlow> = TtlCache::new(cache_capacity);
        Self {
            matcher,
            tcp_cache,
            http_cache,
        }
    }

    /// Captures and analyzes packets on the specified network interface.
    ///
    /// Sends `P0fOutput` through the provided channel.
    ///
    /// # Parameters
    /// - `interface_name`: The name of the network interface to analyze.
    /// - `sender`: A `Sender` to send `P0fOutput` objects back to the caller.
    ///
    /// # Panics
    /// - If the network interface cannot be found or a channel cannot be created.
    pub fn analyze_network(&mut self, interface_name: &str, sender: Sender<P0fOutput>) {
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == interface_name);

        match interface {
            Some(iface) => {
                debug!("Using network interface: {}", iface.name);

                let config = Config {
                    promiscuous: true,
                    ..Config::default()
                };

                let (_tx, mut rx) = match datalink::channel(&iface, config) {
                    Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
                    Ok(_) => {
                        error!("Unhandled channel type for interface: {}", iface.name);
                        return;
                    }
                    Err(e) => {
                        error!(
                            "Unable to create channel for interface {}: {}",
                            iface.name, e
                        );
                        return;
                    }
                };

                loop {
                    match rx.next() {
                        Ok(packet) => {
                            let output = self.analyze_tcp(packet);
                            if sender.send(output).is_err() {
                                error!("Receiver dropped, stopping packet capture");
                                break;
                            }
                        }
                        Err(e) => {
                            error!("Failed to read packet: {}", e);
                        }
                    }
                }
            }
            None => {
                error!("Could not find the network interface: {}", interface_name);
            }
        }
    }

    /// Analyzes a TCP packet and returns a `P0fOutput` object.
    ///
    /// # Parameters
    /// - `packet`: A reference to the TCP packet to analyze.
    ///
    /// # Returns
    /// A `P0fOutput` object containing the analysis results.
    pub fn analyze_tcp(&mut self, packet: &[u8]) -> P0fOutput {
        match ObservablePackage::extract(packet, &mut self.tcp_cache, &mut self.http_cache) {
            Ok(observable_package) => {
                let (syn, syn_ack, mtu, uptime, http_request, http_response) = {
                    let mtu: Option<MTUOutput> =
                        observable_package.mtu.and_then(|observable_mtu| {
                            self.matcher.matching_by_mtu(&observable_mtu.value).map(
                                |(link, _mtu_result)| MTUOutput {
                                    source: observable_package.source.clone(),
                                    destination: observable_package.destination.clone(),
                                    link: link.clone(),
                                    mtu: observable_mtu.value,
                                },
                            )
                        });

                    let syn: Option<SynTCPOutput> =
                        observable_package
                            .tcp_request
                            .map(|observable_tcp| SynTCPOutput {
                                source: observable_package.source.clone(),
                                destination: observable_package.destination.clone(),
                                os_matched: self
                                    .matcher
                                    .matching_by_tcp_request(&observable_tcp.signature)
                                    .map(|(label, _signature, quality)| OSQualityMatched {
                                        os: OperativeSystem::from(label),
                                        quality,
                                    }),
                                sig: observable_tcp.signature,
                            });

                    let syn_ack: Option<SynAckTCPOutput> =
                        observable_package
                            .tcp_response
                            .map(|observable_tcp| SynAckTCPOutput {
                                source: observable_package.source.clone(),
                                destination: observable_package.destination.clone(),
                                os_matched: self
                                    .matcher
                                    .matching_by_tcp_request(&observable_tcp.signature)
                                    .map(|(label, _signature, quality)| OSQualityMatched {
                                        os: OperativeSystem::from(label),
                                        quality,
                                    }),
                                sig: observable_tcp.signature,
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

                    let http_request: Option<HttpRequestOutput> =
                        observable_package.http_request.map(|http_request| {
                            let signature_matcher: Option<(&Label, &Signature, f32)> = self
                                .matcher
                                .matching_by_http_request(&http_request.signature);

                            let ua_matcher: Option<(&String, &Option<String>)> = http_request
                                .user_agent
                                .clone()
                                .and_then(|ua| self.matcher.matching_by_user_agent(ua));

                            let http_diagnosis = http_process::get_diagnostic(
                                http_request.user_agent,
                                ua_matcher,
                                signature_matcher.map(|(label, _signature, _quality)| label),
                            );

                            HttpRequestOutput {
                                source: observable_package.source.clone(),
                                destination: observable_package.destination.clone(),
                                lang: http_request.lang,
                                matched_label: signature_matcher.map(
                                    |(label, _signature, quality)| MatchedLabel {
                                        label: label.clone(),
                                        quality,
                                    },
                                ),
                                diagnosis: http_diagnosis,
                                sig: http_request.signature,
                            }
                        });

                    let http_response: Option<HttpResponseOutput> = observable_package
                        .http_response
                        .map(|http_response| HttpResponseOutput {
                            source: observable_package.source.clone(),
                            destination: observable_package.destination.clone(),
                            matched_label: self
                                .matcher
                                .matching_by_http_response(&http_response.signature)
                                .map(|(label, _signature, quality)| MatchedLabel {
                                    label: label.clone(),
                                    quality,
                                }),
                            diagnosis: HttpDiagnosis::None,
                            sig: http_response.signature,
                        });

                    (syn, syn_ack, mtu, uptime, http_request, http_response)
                };

                P0fOutput {
                    syn,
                    syn_ack,
                    mtu,
                    uptime,
                    http_request,
                    http_response,
                }
            }
            Err(error) => {
                debug!("Fail to process signature: {}", error);
                P0fOutput {
                    syn: None,
                    syn_ack: None,
                    mtu: None,
                    uptime: None,
                    http_request: None,
                    http_response: None,
                }
            }
        }
    }
}
