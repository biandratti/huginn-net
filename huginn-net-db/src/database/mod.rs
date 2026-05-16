//! Database structures: TCP/HTTP sub-databases, collections, and labels.

mod collection;
mod constants;
mod label;
#[cfg(any(feature = "tcp", feature = "http"))]
mod keys;
#[cfg(feature = "http")]
mod http;
#[cfg(feature = "tcp")]
mod tcp;
#[cfg(all(feature = "tcp", feature = "http"))]
mod full;

pub use collection::FingerprintCollection;
pub use label::{Label, Type};
#[cfg(feature = "tcp")]
pub use keys::TcpIndexKey;
#[cfg(feature = "http")]
pub use keys::HttpIndexKey;
#[cfg(feature = "tcp")]
pub use tcp::TcpDatabase;
#[cfg(feature = "http")]
pub use http::HttpDatabase;
#[cfg(all(feature = "tcp", feature = "http"))]
pub use full::Database;
