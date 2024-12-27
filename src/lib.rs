pub mod db;
mod db_parse;
mod display;
mod http;
mod http_process;
mod mtu;
mod p0f_output;
mod process;
mod signature_matcher;
mod tcp;
mod tcp_process;
mod uptime;

use crate::db::Database;
use crate::http::HeaderRegistry;
use crate::http_process::{FlowKey, TcpFlow};
use crate::p0f_output::{
    HttpRequestOutput, HttpResponseOutput, MTUOutput, P0fOutput, SynAckTCPOutput, SynTCPOutput,
    UptimeOutput,
};
use crate::process::ObservablePackage;
use crate::signature_matcher::SignatureMatcher;
use crate::uptime::{Connection, SynData};
use log::{debug, error};
use pnet::datalink;
use pnet::datalink::Config;
use std::sync::mpsc::Sender;
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

        let header_registry: HeaderRegistry = HeaderRegistry::init();
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
                            let output = self.analyze_tcp(packet, &header_registry);
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

    fn analyze_tcp(&mut self, packet: &[u8], header_registry: &HeaderRegistry) -> P0fOutput {
        match ObservablePackage::extract(
            packet,
            &mut self.tcp_cache,
            &mut self.http_cache,
            header_registry,
        ) {
            Ok(observable_package) => {
                let (syn, syn_ack, mtu, uptime, http_request, http_response) = {
                    let mtu: Option<MTUOutput> =
                        observable_package.mtu.and_then(|observable_mtu| {
                            self.matcher
                                .matching_by_mtu(&observable_mtu.value)
                                .map(|(link, _)| MTUOutput {
                                    source: observable_package.source.clone(),
                                    destination: observable_package.destination.clone(),
                                    link: link.clone(),
                                    mtu: observable_mtu.value,
                                })
                        });

                    let syn: Option<SynTCPOutput> =
                        observable_package
                            .tcp_request
                            .map(|observable_tcp| SynTCPOutput {
                                source: observable_package.source.clone(),
                                destination: observable_package.destination.clone(),
                                label: self
                                    .matcher
                                    .matching_by_tcp_request(&observable_tcp.signature)
                                    .map(|(label, _)| label.clone()),
                                sig: observable_tcp.signature,
                            });

                    let syn_ack: Option<SynAckTCPOutput> =
                        observable_package
                            .tcp_response
                            .map(|observable_tcp| SynAckTCPOutput {
                                source: observable_package.source.clone(),
                                destination: observable_package.destination.clone(),
                                label: self
                                    .matcher
                                    .matching_by_tcp_request(&observable_tcp.signature)
                                    .map(|(label, _)| label.clone()),
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

                    let http_request: Option<HttpRequestOutput> = observable_package
                        .http_request
                        .map(|http_request| HttpRequestOutput {
                            source: observable_package.source.clone(),
                            destination: observable_package.destination.clone(),
                            lang: http_request.lang,
                            user_agent: http_request.user_agent,
                            label: self
                                .matcher
                                .matching_by_http_request(&http_request.signature)
                                .map(|(label, _)| label.clone()),
                            sig: http_request.signature,
                        });

                    let http_response: Option<HttpResponseOutput> = observable_package
                        .http_response
                        .map(|http_response| HttpResponseOutput {
                            source: observable_package.source.clone(),
                            destination: observable_package.destination.clone(),
                            label: self
                                .matcher
                                .matching_by_http_response(&http_response.signature)
                                .map(|(label, _)| label.clone()),
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
