#[cfg(feature = "akamai")]
pub mod fingerprint;
pub mod frames;
pub mod parser;
pub mod process;

#[cfg(feature = "akamai")]
pub use fingerprint::Http2FingerprintExtractor;
pub use frames::{Http2Frame, Http2FrameType, HTTP2_CONNECTION_PREFACE};
pub use parser::{
    is_http2_traffic, Http2Config, Http2ParseError, Http2Parser, Http2Request, Http2Response,
    Http2Settings, Http2Stream,
};
pub use process::{parse_http2_request, Http2Processor};
