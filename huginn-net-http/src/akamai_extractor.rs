use crate::akamai::{AkamaiFingerprint, Http2Priority, PseudoHeader, SettingId, SettingParameter};
use crate::http2_parser::{Http2Frame, Http2FrameType};
use crate::http_common::HttpHeader;
use hpack_patched::Decoder;

/// Extract Akamai HTTP/2 fingerprint from HTTP/2 frames
///
/// This function analyzes HTTP/2 connection frames (SETTINGS, WINDOW_UPDATE, PRIORITY, HEADERS)
/// to generate an Akamai fingerprint following the Blackhat EU 2017 specification.
///
/// # Parameters
/// - `frames`: Slice of HTTP/2 frames captured from the connection start
///
/// # Returns
/// - `Some(AkamaiFingerprint)` if enough frames are present
/// - `None` if insufficient data or parsing errors
///
/// # Example
/// ```no_run
/// use huginn_net_http::akamai_extractor::extract_akamai_fingerprint;
/// # use huginn_net_http::http2_parser::Http2Frame;
/// # let frames: Vec<Http2Frame> = vec![];
/// if let Some(fingerprint) = extract_akamai_fingerprint(&frames) {
///     println!("Akamai: {}", fingerprint.fingerprint);
/// }
/// ```
#[must_use]
pub fn extract_akamai_fingerprint(frames: &[Http2Frame]) -> Option<AkamaiFingerprint> {
    let settings = extract_settings_parameters(frames);
    let window_update = extract_window_update(frames);
    let priority_frames = extract_priority_frames(frames);
    let pseudo_header_order = extract_pseudo_header_order(frames);

    // Require at least SETTINGS frame to generate fingerprint
    if settings.is_empty() {
        return None;
    }

    Some(AkamaiFingerprint::new(
        settings,
        window_update,
        priority_frames,
        pseudo_header_order,
    ))
}

/// Extract SETTINGS frame parameters
///
/// SETTINGS frame format (RFC 7540):
/// Each setting is 6 bytes: [id:16][value:32]
fn extract_settings_parameters(frames: &[Http2Frame]) -> Vec<SettingParameter> {
    frames
        .iter()
        .find(|f| f.frame_type == Http2FrameType::Settings && f.stream_id == 0)
        .map(|frame| parse_settings_payload(&frame.payload))
        .unwrap_or_default()
}

#[doc(hidden)]
pub fn parse_settings_payload(payload: &[u8]) -> Vec<SettingParameter> {
    let mut settings = Vec::new();
    let mut offset: usize = 0;

    while offset.saturating_add(6) <= payload.len() {
        if let (Some(&id_h), Some(&id_l), Some(&v0), Some(&v1), Some(&v2), Some(&v3)) = (
            payload.get(offset),
            payload.get(offset.saturating_add(1)),
            payload.get(offset.saturating_add(2)),
            payload.get(offset.saturating_add(3)),
            payload.get(offset.saturating_add(4)),
            payload.get(offset.saturating_add(5)),
        ) {
            let id = u16::from_be_bytes([id_h, id_l]);
            let value = u32::from_be_bytes([v0, v1, v2, v3]);

            settings.push(SettingParameter { id: SettingId::from(id), value });
        }

        offset = offset.saturating_add(6);
    }

    settings
}

/// Extract WINDOW_UPDATE value
///
/// WINDOW_UPDATE frame format (RFC 7540):
/// [R:1][Window Size Increment:31]
fn extract_window_update(frames: &[Http2Frame]) -> u32 {
    frames
        .iter()
        .find(|f| f.frame_type == Http2FrameType::WindowUpdate && f.stream_id == 0)
        .and_then(|frame| parse_window_update_payload(&frame.payload))
        .unwrap_or(0)
}

#[doc(hidden)]
pub fn parse_window_update_payload(payload: &[u8]) -> Option<u32> {
    if payload.len() < 4 {
        return None;
    }

    // Clear reserved bit (first bit)
    let increment = u32::from_be_bytes([payload[0] & 0x7F, payload[1], payload[2], payload[3]]);

    Some(increment)
}

/// Extract PRIORITY frames
///
/// PRIORITY frame format (RFC 7540):
/// [E:1][Stream Dependency:31][Weight:8]
fn extract_priority_frames(frames: &[Http2Frame]) -> Vec<Http2Priority> {
    frames
        .iter()
        .filter(|f| f.frame_type == Http2FrameType::Priority)
        .filter_map(|frame| parse_priority_payload(frame.stream_id, &frame.payload))
        .collect()
}

#[doc(hidden)]
pub fn parse_priority_payload(stream_id: u32, payload: &[u8]) -> Option<Http2Priority> {
    if payload.len() < 5 {
        return None;
    }

    let exclusive = (payload[0] & 0x80) != 0;
    let depends_on = u32::from_be_bytes([payload[0] & 0x7F, payload[1], payload[2], payload[3]]);
    let weight = payload[4];

    Some(Http2Priority { stream_id, exclusive, depends_on, weight })
}

/// Extract pseudo-header order from HEADERS frame
///
/// Pseudo-headers in HTTP/2:
/// - `:method`
/// - `:path`
/// - `:authority`
/// - `:scheme`
/// - `:status` (responses only)
fn extract_pseudo_header_order(frames: &[Http2Frame]) -> Vec<PseudoHeader> {
    // Find first HEADERS frame
    let headers_frame = frames
        .iter()
        .find(|f| f.frame_type == Http2FrameType::Headers && f.stream_id > 0);

    if let Some(frame) = headers_frame {
        if let Ok(headers) = decode_headers(&frame.payload) {
            return headers
                .iter()
                .filter(|h| h.name.starts_with(':'))
                .map(|h| PseudoHeader::from(h.name.as_str()))
                .collect();
        }
    }

    Vec::new()
}

/// Decode HPACK-encoded headers
fn decode_headers(payload: &[u8]) -> Result<Vec<HttpHeader>, hpack_patched::decoder::DecoderError> {
    let mut decoder = Decoder::new();
    let mut headers = Vec::new();

    match decoder.decode(payload) {
        Ok(header_list) => {
            for (position, (name, value)) in header_list.into_iter().enumerate() {
                if let (Ok(name_str), Ok(value_str)) =
                    (String::from_utf8(name), String::from_utf8(value))
                {
                    let source = if name_str.starts_with(':') {
                        crate::http_common::HeaderSource::Http2PseudoHeader
                    } else {
                        crate::http_common::HeaderSource::Http2Header
                    };

                    headers.push(HttpHeader {
                        name: name_str,
                        value: Some(value_str),
                        position,
                        source,
                    });
                }
            }
            Ok(headers)
        }
        Err(e) => Err(e),
    }
}
