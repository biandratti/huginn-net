#[cfg(feature = "akamai")]
pub mod fingerprint;
pub mod frames;
pub mod parser;
pub mod process;

#[cfg(feature = "akamai")]
pub use fingerprint::Http2FingerprintExtractor;
pub use frames::{HTTP2_CONNECTION_PREFACE, Http2Frame, Http2FrameType};
pub use parser::{
    Http2Config, Http2ParseError, Http2Parser, Http2Request, Http2Response, Http2Settings,
    Http2Stream, is_http2_traffic,
};
pub use process::{Http2Processor, parse_http2_request};
