pub mod db;
mod display;
mod http;
mod mtu;
mod p0f_output;
mod packet;
mod parse;
mod signature_matcher;
mod tcp;
mod uptime;

use crate::db::Database;
use crate::p0f_output::{MTUOutput, P0fOutput, SynAckTCPOutput, SynTCPOutput, UptimeOutput};
use crate::packet::ObservableSignature;
use crate::signature_matcher::SignatureMatcher;
use crate::uptime::{Connection, SynData};
use ttl_cache::TtlCache;

pub struct P0f<'a> {
    pub matcher: SignatureMatcher<'a>,
    cache: TtlCache<Connection, SynData>,
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
        let cache: TtlCache<Connection, SynData> = TtlCache::new(cache_capacity);
        Self { matcher, cache }
    }

    /// Analyzes a TCP packet and returns the corresponding `P0fOutput`.
    ///
    /// # Parameters
    /// - `packet`: A byte slice representing the raw TCP packet to analyze.
    ///
    /// # Returns
    /// A `P0fOutput` containing the analysis results, including matched signatures,
    /// observed MTU, uptime information, and other details. If no valid data is observed, an empty output is returned.
    pub fn analyze_tcp(&mut self, packet: &[u8]) -> P0fOutput {
        if let Ok(observable_signature) = ObservableSignature::extract(packet, &mut self.cache) {
            if observable_signature.from_client {

                //println!("MTU {:?}", observable_signature.mtu);
                let mtu: Option<MTUOutput> = if let Some(mtu) = observable_signature.mtu {
                    if let Some((link, _matched_mtu)) = self.matcher.matching_by_mtu(&mtu) {
                        Some(MTUOutput {
                            source: observable_signature.source.clone(),
                            destination: observable_signature.destination.clone(),
                            link: link.clone(),
                            mtu,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                };

                let syn: Option<SynTCPOutput> = if let Some((label, _matched_signature)) = self
                    .matcher
                    .matching_by_tcp_request(&observable_signature.signature)
                {
                    Some(SynTCPOutput {
                        source: observable_signature.source.clone(),
                        destination: observable_signature.destination.clone(),
                        label: Some(label.clone()),
                        sig: observable_signature.signature,
                    })
                } else {
                    Some(SynTCPOutput {
                        source: observable_signature.source.clone(),
                        destination: observable_signature.destination.clone(),
                        label: None,
                        sig: observable_signature.signature,
                    })
                };

                P0fOutput {
                    syn,
                    syn_ack: None,
                    mtu,
                    uptime: None,
                }
            } else {
                let syn_ack: Option<SynAckTCPOutput> = if let Some((label, _matched_signature)) =
                    self.matcher
                        .matching_by_tcp_response(&observable_signature.signature)
                {
                    Some(SynAckTCPOutput {
                        source: observable_signature.source.clone(),
                        destination: observable_signature.destination.clone(),
                        label: Some(label.clone()),
                        sig: observable_signature.signature,
                    })
                } else {
                    Some(SynAckTCPOutput {
                        source: observable_signature.source.clone(),
                        destination: observable_signature.destination.clone(),
                        label: None,
                        sig: observable_signature.signature,
                    })
                };

                P0fOutput {
                    syn: None,
                    syn_ack,
                    mtu: None,
                    uptime: observable_signature.uptime.map(|update| UptimeOutput {
                        source: observable_signature.source,
                        destination: observable_signature.destination,
                        days: update.days,
                        hours: update.hours,
                        min: update.min,
                        up_mod_days: update.up_mod_days,
                        freq: update.freq,
                    }),
                }
            }
        } else {
            P0fOutput {
                syn: None,
                syn_ack: None,
                mtu: None,
                uptime: None,
            }
        }
    }
}
