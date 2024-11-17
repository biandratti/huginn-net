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
use crate::p0f_output::{MTUOutput, P0fOutput, SynAckTCPOutput, UptimeOutput};
use crate::packet::SignatureDetails;
use crate::signature_matcher::SignatureMatcher;
use std::net::IpAddr;
use ttl_cache::TtlCache;

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
struct Connection {
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
}

struct SynData {
    ts1: u32,
    recv_ms: u64,
}
pub struct P0f<'a> {
    pub matcher: SignatureMatcher<'a>,
    cache: TtlCache<Connection, SynData>,
}

impl<'a> P0f<'a> {
    pub fn new(database: &'a Database) -> Self {
        let matcher = SignatureMatcher::new(database);
        let cache: TtlCache<Connection, SynData> = TtlCache::new(100); // TODO: capacity by param...
                                                                       /*let uptime_data = UptimeData {
                                                                           client: None,
                                                                           server: None,
                                                                           sendsyn: false,
                                                                       };*/
        Self {
            matcher,
            cache,
            //uptime_data,
        }
    }

    pub fn analyze_tcp(&mut self, packet: &[u8]) -> P0fOutput {
        if let Ok(signature_details) = SignatureDetails::extract(packet, &mut self.cache) {
            if signature_details.is_client {
                let mtu: Option<MTUOutput> = if let Some(mtu) = signature_details.mtu {
                    if let Some((link, _matched_mtu)) = self.matcher.matching_by_mtu(&mtu) {
                        Some(MTUOutput {
                            client: signature_details.client.clone(),
                            server: signature_details.server.clone(),
                            link: link.clone(),
                            mtu,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                };

                let syn_ack: Option<SynAckTCPOutput> = if let Some((label, _matched_signature)) =
                    self.matcher
                        .matching_by_tcp_request(&signature_details.signature)
                {
                    Some(SynAckTCPOutput {
                        client: signature_details.client.clone(),
                        server: signature_details.server.clone(),
                        is_client: signature_details.is_client,
                        label: Some(label.clone()),
                        sig: signature_details.signature,
                    })
                } else {
                    None
                };

                P0fOutput {
                    syn_ack,
                    mtu,
                    uptime: signature_details.uptime.map(|update| UptimeOutput {
                        client: signature_details.client,
                        server: signature_details.server,
                        days: update.days,
                        hours: update.hours,
                        min: update.min,
                        up_mod_days: update.up_mod_days,
                        freq: update.freq,
                    }),
                }
            } else {
                let syn_ack: Option<SynAckTCPOutput> = if let Some((label, _matched_signature)) =
                    self.matcher
                        .matching_by_tcp_response(&signature_details.signature)
                {
                    Some(SynAckTCPOutput {
                        client: signature_details.client.clone(),
                        server: signature_details.server.clone(),
                        is_client: signature_details.is_client,
                        label: Some(label.clone()),
                        sig: signature_details.signature,
                    })
                } else {
                    None
                };

                P0fOutput {
                    syn_ack,
                    mtu: None,
                    uptime: signature_details.uptime.map(|update| UptimeOutput {
                        client: signature_details.client,
                        server: signature_details.server,
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
                syn_ack: None,
                mtu: None,
                uptime: None,
            }
        }
    }
}
