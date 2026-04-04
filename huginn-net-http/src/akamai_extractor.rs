use crate::akamai::{AkamaiFingerprint, Http2Priority, PseudoHeader, SettingId, SettingParameter};
use crate::error::HuginnNetHttpError;
use crate::http2_parser::Http2Parser;
use crate::http2_parser::{Http2Frame, Http2FrameType};
use crate::http_common::HttpHeader;
use hpack_patched::Decoder;

/// Calculate the total number of bytes consumed by parsing the given frames
///
/// This helper function calculates the total size of all frames (including headers),
/// which is useful for tracking parsing progress when processing incremental data.
///
/// # Parameters
/// - `frames`: Slice of HTTP/2 frames
///
/// # Returns
/// The total number of bytes consumed (sum of `total_size()` for all frames)
///
/// # Example
/// ```no_run
/// use huginn_net_http::akamai_extractor::calculate_frames_bytes_consumed;
/// # use huginn_net_http::http2_parser::Http2Frame;
/// # let frames: Vec<Http2Frame> = vec![];
/// let bytes_consumed = calculate_frames_bytes_consumed(&frames);
/// println!("Consumed {} bytes", bytes_consumed);
/// ```
#[must_use]
pub fn calculate_frames_bytes_consumed(frames: &[Http2Frame]) -> usize {
    frames.iter().map(|f| f.total_size()).sum()
}

/// Extract Akamai HTTP/2 fingerprint directly from raw bytes
///
/// This is a convenience function that combines parsing HTTP/2 frames and extracting
/// the Akamai fingerprint in a single call. Automatically handles the HTTP/2 connection
/// preface if present.
///
/// # Parameters
/// - `data`: Raw HTTP/2 frame data (may include connection preface)
///
/// # Returns
/// - `Ok(AkamaiFingerprint)` if enough frames are present and fingerprint can be extracted
/// - `Err(NoSettingsFrame)` if no SETTINGS frame was found
/// - `Err(MalformedPseudoHeaders)` if a HEADERS frame was present but its payload is corrupt
/// - `Err(Parse)` if the raw bytes could not be parsed as HTTP/2 frames
///
/// # Example
/// ```no_run
/// use huginn_net_http::akamai_extractor::extract_akamai_fingerprint_from_bytes;
///
/// let data = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x06\x04\x00\x00\x00\x00\x00";
/// match extract_akamai_fingerprint_from_bytes(data) {
///     Ok(fingerprint) => println!("Akamai: {}", fingerprint.fingerprint),
///     Err(e) => eprintln!("Extraction failed: {e}"),
/// }
/// ```
pub fn extract_akamai_fingerprint_from_bytes(
    data: &[u8],
) -> Result<AkamaiFingerprint, HuginnNetHttpError> {
    let parser = Http2Parser::new();
    let (frames, _) = parser
        .parse_frames_skip_preface(data)
        .map_err(|e| HuginnNetHttpError::Parse(e.to_string()))?;
    extract_akamai_fingerprint(&frames)
}

/// Extract Akamai HTTP/2 fingerprint from HTTP/2 frames
///
/// This function analyzes HTTP/2 connection frames (SETTINGS, WINDOW_UPDATE, PRIORITY, HEADERS)
/// to generate an Akamai fingerprint following the Blackhat EU 2017 specification.
///
/// # Parameters
/// - `frames`: Slice of HTTP/2 frames captured from the connection start
///
/// # Returns
/// - `Ok(AkamaiFingerprint)` if enough frames are present and all fields are valid
/// - `Err(NoSettingsFrame)` if no SETTINGS frame was found (insufficient data)
/// - `Err(MalformedPseudoHeaders)` if a HEADERS frame was present but its payload is corrupt —
///   this is a strong indicator of spoofed or bot-generated traffic
///
/// # Example
/// ```no_run
/// use huginn_net_http::akamai_extractor::extract_akamai_fingerprint;
/// # use huginn_net_http::http2_parser::Http2Frame;
/// # let frames: Vec<Http2Frame> = vec![];
/// match extract_akamai_fingerprint(&frames) {
///     Ok(fingerprint) => println!("Akamai: {}", fingerprint.fingerprint),
///     Err(e) => eprintln!("Extraction failed: {e}"),
/// }
/// ```
pub fn extract_akamai_fingerprint(
    frames: &[Http2Frame],
) -> Result<AkamaiFingerprint, HuginnNetHttpError> {
    let settings = extract_settings_parameters(frames);
    if settings.is_empty() {
        return Err(HuginnNetHttpError::NoSettingsFrame);
    }
    let window_update = extract_window_update(frames);
    let priority_frames = extract_priority_frames(frames);
    let pseudo_header_order = extract_pseudo_header_order(frames)?;
    Ok(AkamaiFingerprint::new(
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

// RFC 7540 §6.2 HEADERS flags relevant for payload layout
const FLAG_PADDED: u8 = 0x08;
const FLAG_PRIORITY: u8 = 0x20;

/// Extract pseudo-header order from HEADERS frame.
///
/// Returns:
/// - `Ok(vec![])` if no HEADERS frame is present yet (legitimate — data may arrive later).
/// - `Ok(headers)` if decoded successfully.
/// - `Err(MalformedPseudoHeaders)` if a HEADERS frame is present but its payload is corrupt.
///
/// Pseudo-headers in HTTP/2: `:method`, `:path`, `:authority`, `:scheme`, `:status` (responses).
fn extract_pseudo_header_order(
    frames: &[Http2Frame],
) -> Result<Vec<PseudoHeader>, HuginnNetHttpError> {
    // Find first HEADERS frame on a request stream (stream_id > 0)
    let headers_frame = frames
        .iter()
        .find(|f| f.frame_type == Http2FrameType::Headers && f.stream_id > 0);

    let Some(frame) = headers_frame else {
        return Ok(Vec::new()); // no HEADERS frame yet — legitimate, not an error
    };

    // RFC 7540 §6.2: strip optional leading fields before the HPACK block.
    // The payload layout is:
    //   [Pad Length (1B, if PADDED)]
    //   [Exclusive(1b) + Stream Dependency(31b) + Weight(1B) = 5B, if PRIORITY]
    //   <Header Block Fragment>
    //   [Padding]
    let mut hpack_payload = frame.payload.as_slice();

    if frame.flags & FLAG_PADDED != 0 {
        let Some((&pad_len, rest)) = hpack_payload.split_first() else {
            return Err(HuginnNetHttpError::MalformedPseudoHeaders(
                "PADDED flag set but payload is empty".into(),
            ));
        };
        let pad = pad_len as usize;
        let end = rest.len().checked_sub(pad).ok_or_else(|| {
            HuginnNetHttpError::MalformedPseudoHeaders(format!(
                "pad length {pad} exceeds remaining payload of {} bytes",
                rest.len()
            ))
        })?;
        hpack_payload = &rest[..end];
    }

    if frame.flags & FLAG_PRIORITY != 0 {
        if hpack_payload.len() < 5 {
            return Err(HuginnNetHttpError::MalformedPseudoHeaders(format!(
                "PRIORITY flag set but only {} bytes remain (need 5)",
                hpack_payload.len()
            )));
        }
        hpack_payload = &hpack_payload[5..];
    }

    decode_headers(hpack_payload)
        .map(|headers| {
            headers
                .iter()
                .filter(|h| h.name.starts_with(':'))
                .map(|h| PseudoHeader::from(h.name.as_str()))
                .collect()
        })
        .map_err(|e| {
            HuginnNetHttpError::MalformedPseudoHeaders(format!("HPACK decode error: {e:?}"))
        })
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
