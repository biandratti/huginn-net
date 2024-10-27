pub mod db;
mod display;
mod http;
mod mtu;
mod p0f_output;
mod packet;
mod parse;
mod signature_matcher;
mod tcp;

use crate::db::Database;
use crate::p0f_output::P0fOutput;
use crate::packet::SignatureDetails;
use crate::signature_matcher::SignatureMatcher;

pub struct P0f<'a> {
    pub matcher: SignatureMatcher<'a>,
}

impl<'a> P0f<'a> {
    pub fn new(database: &'a Database) -> Self {
        let matcher = SignatureMatcher::new(database);
        Self { matcher }
    }

    pub fn analyze_tcp(&self, packet: &[u8]) -> Option<P0fOutput> {
        if let Ok(signature_details) = SignatureDetails::extract(packet) {
            if signature_details.is_client {
                if let Some((label, _matched_signature)) = self
                    .matcher
                    .matching_by_tcp_request(&signature_details.signature)
                {
                    return Some(P0fOutput {
                        client: signature_details.client,
                        server: signature_details.server,
                        is_client: signature_details.is_client,
                        label: Some(label.clone()),
                        sig: signature_details.signature,
                    });
                }
            } else {
                if let Some((label, _matched_signature)) = self
                    .matcher
                    .matching_by_tcp_response(&signature_details.signature)
                {
                    return Some(P0fOutput {
                        client: signature_details.client,
                        server: signature_details.server,
                        is_client: signature_details.is_client,
                        label: Some(label.clone()),
                        sig: signature_details.signature,
                    });
                }
            }
        }
        None
    }
}
