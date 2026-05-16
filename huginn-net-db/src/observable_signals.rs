#[cfg(feature = "http")]
pub use huginn_net_http::observable::{HttpRequestObservation, HttpResponseObservation};
#[cfg(feature = "tcp")]
pub use huginn_net_tcp::observable::TcpObservation;
