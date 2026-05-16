//! TLS fingerprinting and JA4 analysis.
//!
//! ## Cargo Features
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `stable-v1` | No | Adds [`Signature::generate_ja4_stable_v1`] / [`ObservableTlsClient::ja4_stable_v1`], ephemeral extensions excluded for stable fingerprints |

#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod analyzer;
pub mod error;
pub mod filter;
pub mod fingerprint;
pub mod output;
pub mod parser;
pub mod process;

// Backward-compat module shims — re-export so old paths still compile
// (types are the same objects, no mismatch)
pub mod tls {
    pub use crate::fingerprint::*;
}
pub mod observable {
    pub use crate::fingerprint::{ObservableTlsClient, ObservableTlsPackage};
}
pub mod tls_process {
    pub use crate::process::tls::*;
}
pub mod tls_client_hello_reader {
    pub use crate::parser::client_hello_reader::*;
}
pub mod packet_hash {
    pub use crate::parser::hash::*;
}
pub mod packet_parser {
    pub use crate::parser::packet::*;
}
pub mod parallel {
    pub use crate::process::parallel::*;
}
pub mod raw_filter {
    pub use crate::filter::raw::*;
}

// Re-exports — public API surface
pub use analyzer::HuginnNetTls;
pub use error::*;
pub use filter::*;
pub use fingerprint::*;
pub use output::*;
pub use parser::TlsClientHelloReader;
pub use process::parallel::{DispatchResult, PoolStats, WorkerPool, WorkerStats};
pub use process::tls::{
    parse_tls_client_hello, parse_tls_client_hello_ja4, process_tls_ipv4, process_tls_ipv6,
};
pub use process::{process_ipv4_packet, process_ipv6_packet, FlowKey, ObservablePackage};
