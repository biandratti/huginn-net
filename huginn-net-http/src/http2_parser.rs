use crate::http;
use crate::http_common::{HeaderSource, HttpCookie, HttpHeader, ParsingMetadata};
use hpack_patched::Decoder;
use std::cell::RefCell;
use std::collections::HashMap;
use std::time::Instant;

pub const HTTP2_CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[derive(Debug, Clone, PartialEq)]
#[repr(u8)]
pub enum Http2FrameType {
    Data = 0x0,
    Headers = 0x1,
    Priority = 0x2,
    RstStream = 0x3,
    Settings = 0x4,
    PushPromise = 0x5,
    Ping = 0x6,
    GoAway = 0x7,
    WindowUpdate = 0x8,
    Continuation = 0x9,
    Unknown(u8),
}

impl From<u8> for Http2FrameType {
    fn from(frame_type: u8) -> Self {
        match frame_type {
            0x0 => Http2FrameType::Data,
            0x1 => Http2FrameType::Headers,
            0x2 => Http2FrameType::Priority,
            0x3 => Http2FrameType::RstStream,
            0x4 => Http2FrameType::Settings,
            0x5 => Http2FrameType::PushPromise,
            0x6 => Http2FrameType::Ping,
            0x7 => Http2FrameType::GoAway,
            0x8 => Http2FrameType::WindowUpdate,
            0x9 => Http2FrameType::Continuation,
            other => Http2FrameType::Unknown(other),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Http2Frame {
    pub frame_type: Http2FrameType,
    pub stream_id: u32,
    pub flags: u8,
    pub payload: Vec<u8>,
    pub length: u32,
}

impl Http2Frame {
    /// Creates a new HTTP/2 frame
    ///
    /// # Parameters
    /// - `frame_type_byte`: Raw frame type byte (0x0-0x9 for standard types)
    /// - `flags`: Frame flags byte
    /// - `stream_id`: Stream identifier
    /// - `payload`: Frame payload data
    ///
    /// # Example
    /// ```no_run
    /// use huginn_net_http::Http2Frame;
    ///
    /// // Create a SETTINGS frame (type 0x4)
    /// let frame = Http2Frame::new(0x4, 0x0, 0, vec![0x00, 0x03, 0x00, 0x00, 0x00, 0x64]);
    /// ```
    #[must_use]
    pub fn new(frame_type_byte: u8, flags: u8, stream_id: u32, payload: Vec<u8>) -> Self {
        let length = payload.len() as u32;
        Self {
            frame_type: Http2FrameType::from(frame_type_byte),
            stream_id,
            flags,
            payload,
            length,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Http2Settings {
    pub header_table_size: Option<u32>,
    pub enable_push: Option<bool>,
    pub max_concurrent_streams: Option<u32>,
    pub initial_window_size: Option<u32>,
    pub max_frame_size: Option<u32>,
    pub max_header_list_size: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Http2Stream {
    pub stream_id: u32,
    pub headers: Vec<HttpHeader>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub authority: Option<String>,
    pub scheme: Option<String>,
    pub status: Option<u16>,
}

pub struct Http2Config {
    pub max_frame_size: u32,
    pub max_streams: u32,
    pub enable_hpack: bool,
    pub strict_parsing: bool,
}

impl Default for Http2Config {
    fn default() -> Self {
        Self {
            max_frame_size: 16384,
            max_streams: 100,
            enable_hpack: false,
            strict_parsing: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Http2Request {
    pub method: String,
    pub path: String,
    pub authority: Option<String>,
    pub scheme: Option<String>,
    pub version: http::Version,
    pub headers: Vec<HttpHeader>,
    pub cookies: Vec<HttpCookie>,
    pub referer: Option<String>,
    pub stream_id: u32,
    pub parsing_metadata: ParsingMetadata,
    pub frame_sequence: Vec<Http2FrameType>,
    pub settings: Http2Settings,
}

#[derive(Debug, Clone)]
pub struct Http2Response {
    pub status: u16,
    pub version: http::Version,
    pub headers: Vec<HttpHeader>,
    pub stream_id: u32,
    pub parsing_metadata: ParsingMetadata,
    pub frame_sequence: Vec<Http2FrameType>,
    pub server: Option<String>,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Http2ParseError {
    InvalidPreface,
    InvalidFrameHeader,
    InvalidFrameLength(u32),
    InvalidStreamId(u32),
    FrameTooLarge(u32),
    MissingRequiredHeaders,
    InvalidPseudoHeader(String),
    IncompleteFrame,
    InvalidUtf8,
    UnsupportedFeature(String),
    HpackDecodingFailed,
}

impl std::fmt::Display for Http2ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPreface => write!(f, "Invalid HTTP/2 connection preface"),
            Self::InvalidFrameHeader => write!(f, "Invalid HTTP/2 frame header"),
            Self::InvalidFrameLength(len) => write!(f, "Invalid frame length: {len}"),
            Self::InvalidStreamId(id) => write!(f, "Invalid stream ID: {id}"),
            Self::FrameTooLarge(size) => write!(f, "Frame too large: {size} bytes"),
            Self::MissingRequiredHeaders => write!(f, "Missing required pseudo-headers"),
            Self::InvalidPseudoHeader(name) => write!(f, "Invalid pseudo-header: {name}"),
            Self::IncompleteFrame => write!(f, "Incomplete HTTP/2 frame"),
            Self::InvalidUtf8 => write!(f, "Invalid UTF-8 in HTTP/2 data"),
            Self::UnsupportedFeature(feature) => write!(f, "Unsupported feature: {feature}"),
            Self::HpackDecodingFailed => write!(f, "HPACK decoding failed"),
        }
    }
}

impl std::error::Error for Http2ParseError {}

/// HTTP/2 Protocol Parser
///
/// Provides parsing capabilities for HTTP/2 requests and responses according to RFC 7540.
/// Supports HPACK header compression and handles various frame types.
///
/// # Thread Safety
///
/// **This parser is NOT thread-safe.** Each thread should create its own instance.
/// The internal HPACK decoder maintains state and uses `RefCell` for interior mutability.
pub struct Http2Parser<'a> {
    config: Http2Config,
    hpack_decoder: RefCell<Decoder<'a>>,
}

impl<'a> Default for Http2Parser<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> Http2Parser<'a> {
    pub fn new() -> Self {
        Self { config: Http2Config::default(), hpack_decoder: RefCell::new(Decoder::new()) }
    }

    pub fn with_config(config: Http2Config) -> Self {
        Self { config, hpack_decoder: RefCell::new(Decoder::new()) }
    }

    /// Parse HTTP/2 request from binary data
    pub fn parse_request(&self, data: &[u8]) -> Result<Option<Http2Request>, Http2ParseError> {
        let start_time = Instant::now();

        if !self.has_http2_preface(data) {
            return Err(Http2ParseError::InvalidPreface);
        }

        let frame_data = &data[HTTP2_CONNECTION_PREFACE.len()..];
        let frames = self.parse_frames(frame_data)?;

        if frames.is_empty() {
            return Ok(None);
        }

        let Some(stream_id) = self.find_primary_stream(&frames) else {
            return Ok(None);
        };
        let stream = self.build_stream(stream_id, &frames)?;

        let method = stream
            .method
            .ok_or(Http2ParseError::MissingRequiredHeaders)?;
        let path = stream.path.ok_or(Http2ParseError::MissingRequiredHeaders)?;

        let parsing_time = start_time.elapsed().as_nanos() as u64;
        let frame_sequence: Vec<Http2FrameType> =
            frames.iter().map(|f| f.frame_type.clone()).collect();

        let mut headers = Vec::new();
        let mut headers_map = HashMap::new();
        let mut referer: Option<String> = None;
        let mut cookie_headers: Vec<&HttpHeader> = Vec::new();

        for header in &stream.headers {
            let header_name_lower = header.name.to_lowercase();

            if header_name_lower == "cookie" {
                cookie_headers.push(header);
            } else if header_name_lower == "referer" {
                if let Some(ref value) = header.value {
                    referer = Some(value.clone());
                }
            } else {
                if let Some(ref value) = header.value {
                    headers_map.insert(header_name_lower, value.clone());
                }
                // Clone the header to move into the filtered headers vec
                headers.push(header.clone());
            }
        }

        let cookies = self.parse_cookies_from_headers(&cookie_headers);

        let metadata = ParsingMetadata {
            header_count: headers.len(),
            duplicate_headers: Vec::new(),
            case_variations: HashMap::new(),
            parsing_time_ns: parsing_time,
            has_malformed_headers: false,
            request_line_length: 0,
            total_headers_length: headers
                .iter()
                .map(|h| {
                    h.name
                        .len()
                        .saturating_add(h.value.as_ref().map_or(0, |v| v.len()))
                })
                .sum(),
        };

        Ok(Some(Http2Request {
            method,
            path,
            authority: stream.authority,
            scheme: stream.scheme,
            version: http::Version::V20,
            headers,
            cookies,
            referer,
            stream_id,
            parsing_metadata: metadata,
            frame_sequence,
            settings: self.extract_settings(&frames),
        }))
    }

    /// Parse HTTP/2 response from binary data
    pub fn parse_response(&self, data: &[u8]) -> Result<Option<Http2Response>, Http2ParseError> {
        let start_time = Instant::now();

        let frames = self.parse_frames(data)?;

        if frames.is_empty() {
            return Ok(None);
        }

        let Some(stream_id) = self.find_primary_stream(&frames) else {
            return Ok(None);
        };
        let stream = self.build_stream(stream_id, &frames)?;

        let status = stream
            .status
            .ok_or(Http2ParseError::MissingRequiredHeaders)?;

        let parsing_time = start_time.elapsed().as_nanos() as u64;
        let frame_sequence: Vec<Http2FrameType> =
            frames.iter().map(|f| f.frame_type.clone()).collect();

        let mut headers_map = HashMap::new();
        for header in &stream.headers {
            if let Some(ref value) = header.value {
                headers_map.insert(header.name.to_lowercase(), value.clone());
            }
        }

        let metadata = ParsingMetadata {
            header_count: stream.headers.len(),
            duplicate_headers: Vec::new(),
            case_variations: HashMap::new(),
            parsing_time_ns: parsing_time,
            has_malformed_headers: false,
            request_line_length: 0,
            total_headers_length: stream
                .headers
                .iter()
                .map(|h| {
                    h.name
                        .len()
                        .saturating_add(h.value.as_ref().map_or(0, |v| v.len()))
                })
                .sum(),
        };

        Ok(Some(Http2Response {
            status,
            version: http::Version::V20,
            headers: stream.headers,
            stream_id,
            parsing_metadata: metadata,
            frame_sequence,
            server: headers_map.get("server").cloned(),
            content_type: headers_map.get("content-type").cloned(),
        }))
    }

    fn has_http2_preface(&self, data: &[u8]) -> bool {
        data.starts_with(HTTP2_CONNECTION_PREFACE)
    }

    fn parse_frames(&self, data: &[u8]) -> Result<Vec<Http2Frame>, Http2ParseError> {
        let mut frames = Vec::new();
        let mut remaining = data;

        while remaining.len() >= 9 {
            // Check if we have enough data for the complete frame
            let frame_length = u32::from_be_bytes([0, remaining[0], remaining[1], remaining[2]]);
            let frame_total_size = match usize::try_from(9_u32.saturating_add(frame_length)) {
                Ok(size) => size,
                Err(_) => break, // Frame too large, skip remaining data
            };

            if remaining.len() < frame_total_size {
                // Incomplete frame at the end, stop parsing here
                break;
            }

            match self.parse_single_frame(remaining) {
                Ok((rest, frame)) => {
                    frames.push(frame);
                    remaining = rest;
                }
                Err(_) => {
                    // Skip this frame and continue
                    break;
                }
            }
        }

        Ok(frames)
    }

    fn parse_single_frame<'b>(
        &self,
        data: &'b [u8],
    ) -> Result<(&'b [u8], Http2Frame), Http2ParseError> {
        if data.len() < 9 {
            return Err(Http2ParseError::IncompleteFrame);
        }

        let length = u32::from_be_bytes([0, data[0], data[1], data[2]]);
        let frame_type_byte = data[3];
        let flags = data[4];
        let stream_id = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) & 0x7FFF_FFFF;

        if length > self.config.max_frame_size {
            return Err(Http2ParseError::FrameTooLarge(length));
        }

        let frame_total_size = match usize::try_from(9_u32.saturating_add(length)) {
            Ok(size) => size,
            Err(_) => return Err(Http2ParseError::FrameTooLarge(length)),
        };

        if data.len() < frame_total_size {
            return Err(Http2ParseError::IncompleteFrame);
        }

        let payload_start = 9;
        let payload_end = frame_total_size;
        let payload = data[payload_start..payload_end].to_vec();

        let frame = Http2Frame {
            frame_type: Http2FrameType::from(frame_type_byte),
            stream_id,
            flags,
            payload,
            length,
        };

        Ok((&data[payload_end..], frame))
    }

    fn find_primary_stream(&self, frames: &[Http2Frame]) -> Option<u32> {
        for frame in frames {
            if frame.stream_id > 0 && frame.frame_type == Http2FrameType::Headers {
                return Some(frame.stream_id);
            }
        }
        None
    }

    fn build_stream(
        &self,
        stream_id: u32,
        frames: &[Http2Frame],
    ) -> Result<Http2Stream, Http2ParseError> {
        let mut headers = Vec::new();
        let mut method = None;
        let mut path = None;
        let mut authority = None;
        let mut scheme = None;
        let mut status = None;

        let stream_frames: Vec<&Http2Frame> =
            frames.iter().filter(|f| f.stream_id == stream_id).collect();

        for frame in stream_frames {
            match frame.frame_type {
                Http2FrameType::Headers | Http2FrameType::Continuation => {
                    let frame_headers = self.parse_headers_payload(&frame.payload)?;
                    for header in frame_headers {
                        match header.name.as_str() {
                            ":method" => method = Some(header.value.clone().unwrap_or_default()),
                            ":path" => path = Some(header.value.clone().unwrap_or_default()),
                            ":authority" => {
                                authority = Some(header.value.clone().unwrap_or_default())
                            }
                            ":scheme" => scheme = Some(header.value.clone().unwrap_or_default()),
                            ":status" => {
                                status = header.value.as_ref().and_then(|v| v.parse().ok())
                            }
                            _ => headers.push(header),
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(Http2Stream { stream_id, headers, method, path, authority, scheme, status })
    }

    fn parse_headers_payload(&self, payload: &[u8]) -> Result<Vec<HttpHeader>, Http2ParseError> {
        let headers = self
            .hpack_decoder
            .borrow_mut()
            .decode(payload)
            .map_err(|_| Http2ParseError::HpackDecodingFailed)?;

        let mut http_headers = Vec::new();

        for (position, (name, value)) in headers.iter().enumerate() {
            let name_str = String::from_utf8_lossy(name).to_string();
            let value_str = String::from_utf8_lossy(value);
            let value_opt = if value_str.is_empty() {
                None
            } else {
                Some(value_str.to_string())
            };

            http_headers.push(HttpHeader {
                name: name_str,
                value: value_opt,
                position,
                source: HeaderSource::Http2Header,
            });
        }

        Ok(http_headers)
    }

    fn extract_settings(&self, frames: &[Http2Frame]) -> Http2Settings {
        let mut settings = Http2Settings::default();

        for frame in frames {
            if frame.frame_type == Http2FrameType::Settings {
                let payload = &frame.payload;
                for chunk in payload.chunks_exact(6) {
                    if chunk.len() == 6 {
                        let id = u16::from_be_bytes([chunk[0], chunk[1]]);
                        let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);

                        match id {
                            1 => settings.header_table_size = Some(value),
                            2 => settings.enable_push = Some(value != 0),
                            3 => settings.max_concurrent_streams = Some(value),
                            4 => settings.initial_window_size = Some(value),
                            5 => settings.max_frame_size = Some(value),
                            6 => settings.max_header_list_size = Some(value),
                            _ => {}
                        }
                    }
                }
            }
        }

        settings
    }

    /// HTTP/2 cookie parsing - handles multiple cookie headers according to RFC 7540
    pub fn parse_cookies_from_headers(&self, cookie_headers: &[&HttpHeader]) -> Vec<HttpCookie> {
        let mut cookies = Vec::new();
        let mut position = 0;

        for header in cookie_headers {
            if let Some(ref cookie_value) = header.value {
                // Each cookie header can contain multiple cookies separated by '; '
                for cookie_str in cookie_value.split(';') {
                    let cookie_str = cookie_str.trim();
                    if cookie_str.is_empty() {
                        continue;
                    }

                    if let Some(eq_pos) = cookie_str.find('=') {
                        let name = cookie_str[..eq_pos].trim().to_string();
                        let value = Some(
                            cookie_str
                                .get(eq_pos.saturating_add(1)..)
                                .unwrap_or("")
                                .trim()
                                .to_string(),
                        );
                        cookies.push(HttpCookie { name, value, position });
                    } else {
                        cookies.push(HttpCookie {
                            name: cookie_str.to_string(),
                            value: None,
                            position,
                        });
                    }
                    position = position.saturating_add(1);
                }
            }
        }

        cookies
    }
}

pub fn is_http2_traffic(data: &[u8]) -> bool {
    data.starts_with(HTTP2_CONNECTION_PREFACE)
}
