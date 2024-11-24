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
use crate::packet::SignatureDetails;
use crate::signature_matcher::SignatureMatcher;
use crate::uptime::{Connection, SynData};
use ttl_cache::TtlCache;

pub struct P0f<'a> {
    pub matcher: SignatureMatcher<'a>,
    cache: TtlCache<Connection, SynData>,
}

impl<'a> P0f<'a> {
    pub fn new(database: &'a Database, cache_capacity: usize) -> Self {
        let matcher: SignatureMatcher = SignatureMatcher::new(database);
        let cache: TtlCache<Connection, SynData> = TtlCache::new(cache_capacity);
        Self { matcher, cache }
    }

    pub fn analyze_tcp(&mut self, packet: &[u8]) -> P0fOutput {
        if let Ok(signature_details) = SignatureDetails::extract(packet, &mut self.cache) {
            if signature_details.is_client {
                let mtu: Option<MTUOutput> = if let Some(mtu) = signature_details.mtu {
                    if let Some((link, _matched_mtu)) = self.matcher.matching_by_mtu(&mtu) {
                        Some(MTUOutput {
                            source: signature_details.source.clone(),
                            destination: signature_details.destination.clone(),
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
                    .matching_by_tcp_request(&signature_details.signature)
                {
                    Some(SynTCPOutput {
                        source: signature_details.source.clone(),
                        destination: signature_details.destination.clone(),
                        label: Some(label.clone()),
                        sig: signature_details.signature,
                    })
                } else {
                    None
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
                        .matching_by_tcp_response(&signature_details.signature)
                {
                    Some(SynAckTCPOutput {
                        source: signature_details.source.clone(),
                        destination: signature_details.destination.clone(),
                        label: Some(label.clone()),
                        sig: signature_details.signature,
                    })
                } else {
                    None
                };

                P0fOutput {
                    syn: None,
                    syn_ack,
                    mtu: None,
                    uptime: signature_details.uptime.map(|update| UptimeOutput {
                        source: signature_details.source,
                        destination: signature_details.destination,
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
