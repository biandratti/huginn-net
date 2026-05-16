//! Database structures: TCP/HTTP sub-databases, collections, and labels.

mod collection;
mod constants;
#[cfg(all(feature = "tcp", feature = "http"))]
mod full;
#[cfg(feature = "http")]
mod http;
#[cfg(any(feature = "tcp", feature = "http"))]
mod keys;
mod label;
#[cfg(feature = "tcp")]
mod tcp;

pub use collection::FingerprintCollection;
#[cfg(all(feature = "tcp", feature = "http"))]
pub use full::Database;
#[cfg(feature = "http")]
pub use http::HttpDatabase;
#[cfg(feature = "http")]
pub use keys::HttpIndexKey;
#[cfg(feature = "tcp")]
pub use keys::TcpIndexKey;
pub use label::{Label, Type};
#[cfg(feature = "tcp")]
pub use tcp::TcpDatabase;
