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

struct SynData {
    ts1: u32,
    recv_ms: u64,
}
struct UptimeData {
    client: Option<SynData>,
    server: Option<SynData>,
}

pub struct P0f<'a> {
    pub matcher: SignatureMatcher<'a>,
    uptime_data: UptimeData,
}

impl<'a> P0f<'a> {
    pub fn new(database: &'a Database) -> Self {
        let matcher = SignatureMatcher::new(database);
        let uptime_data = UptimeData {
            client: None,
            server: None,
        };
        Self {
            matcher,
            uptime_data,
        }
    }

    pub fn analyze_tcp(&mut self, packet: &[u8]) -> P0fOutput {
        if let Ok(signature_details) = SignatureDetails::extract(packet, &mut self.uptime_data) {
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
