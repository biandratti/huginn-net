//! Accumulates a connection's client HTTP/2 bytes until the fingerprint is complete.
//!
//! Used by the packet pipeline (`akamai-cleartext`, `akamai-keylog`). Unlike the incremental
//! [`crate::Http2FingerprintExtractor`], it waits for the first client HEADERS frame before
//! extracting, so SETTINGS / WINDOW_UPDATE / PRIORITY and the pseudo-header order are all
//! included even when they arrive in different TCP segments or TLS records. The result is
//! [`extract_akamai_fingerprint`] over the same frames, so it is byte-identical to the
//! standalone API for the same plaintext.

use super::AkamaiFingerprint;
use super::extractor::extract_akamai_fingerprint;
use crate::http2::{HTTP2_CONNECTION_PREFACE, Http2FrameType, Http2Parser};

/// Default cap on buffered client bytes per connection before giving up.
// Used by the cleartext pipeline (US2); only tests use it until then.
#[cfg(test)]
pub(crate) const DEFAULT_ACCUMULATOR_LIMIT: usize = 64 * 1024;

/// Why a connection cannot produce an Akamai fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AccumulatorError {
    /// The client bytes do not start with the HTTP/2 connection preface.
    NotHttp2,
    /// More than the configured limit was buffered without a complete HEADERS frame.
    TooLarge,
    /// HTTP/2 frames are present but the fingerprint fields are corrupt.
    Malformed,
}

pub(crate) struct AkamaiAccumulator {
    buf: Vec<u8>,
    limit: usize,
}

impl AkamaiAccumulator {
    pub(crate) fn new(limit: usize) -> Self {
        // Reserve up front so the buffer rarely reallocates (decrypted bytes are wiped on drop
        // with `akamai-keylog`, and a reallocation would leave an unwiped copy behind).
        Self { buf: Vec::with_capacity(limit.min(16 * 1024)), limit }
    }

    /// Appends client bytes (starting at the HTTP/2 preface). Returns the fingerprint once the
    /// first client HEADERS frame is complete.
    pub(crate) fn push(
        &mut self,
        data: &[u8],
    ) -> Result<Option<AkamaiFingerprint>, AccumulatorError> {
        self.buf.extend_from_slice(data);
        if self.buf.len() > self.limit {
            return Err(AccumulatorError::TooLarge);
        }
        let check = self.buf.len().min(HTTP2_CONNECTION_PREFACE.len());
        if self.buf[..check] != HTTP2_CONNECTION_PREFACE[..check] {
            return Err(AccumulatorError::NotHttp2);
        }
        if self.buf.len() < HTTP2_CONNECTION_PREFACE.len() {
            return Ok(None);
        }

        let parser = Http2Parser::new();
        let (frames, _) = parser
            .parse_frames_skip_preface(&self.buf)
            .map_err(|_| AccumulatorError::Malformed)?;
        let has_headers = frames
            .iter()
            .any(|f| f.frame_type == Http2FrameType::Headers && f.stream_id != 0);
        if !has_headers {
            return Ok(None);
        }
        extract_akamai_fingerprint(&frames)
            .map(Some)
            .map_err(|_| AccumulatorError::Malformed)
    }

    /// Bytes currently buffered.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn len(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(feature = "akamai-keylog")]
impl Drop for AkamaiAccumulator {
    fn drop(&mut self) {
        // May hold decrypted application data (FR-008).
        zeroize::Zeroize::zeroize(&mut self.buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::akamai::extractor::extract_akamai_fingerprint_from_bytes;

    fn frame(ftype: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let len = u32::try_from(payload.len()).unwrap_or(0).to_be_bytes();
        let mut f = vec![len[1], len[2], len[3], ftype, flags];
        f.extend_from_slice(&stream.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    fn client_bytes() -> (Vec<u8>, Vec<u8>) {
        let mut first = HTTP2_CONNECTION_PREFACE.to_vec();
        first.extend(frame(4, 0, 0, &[0, 1, 0, 1, 0, 0, 0, 4, 0, 0x60, 0, 0]));
        first.extend(frame(8, 0, 0, &[0, 0xEF, 0, 1]));
        // :method GET, :path /, :scheme https, :authority (literal, indexed name 1)
        let mut block = vec![0x82, 0x84, 0x87, 0x41, 4];
        block.extend_from_slice(b"host");
        let headers = frame(1, 0x05, 1, &block);
        (first, headers)
    }

    #[test]
    fn waits_for_headers_then_matches_standalone_extractor() {
        let (first, headers) = client_bytes();
        let mut acc = AkamaiAccumulator::new(DEFAULT_ACCUMULATOR_LIMIT);
        assert_eq!(acc.push(&first), Ok(None), "no HEADERS yet");
        let fp = match acc.push(&headers) {
            Ok(Some(fp)) => fp,
            other => panic!("expected a fingerprint, got {other:?}"),
        };
        let mut all = first.clone();
        all.extend_from_slice(&headers);
        let standalone = match extract_akamai_fingerprint_from_bytes(&all) {
            Ok(fp) => fp,
            Err(e) => panic!("standalone must succeed: {e}"),
        };
        assert_eq!(fp, standalone);
        assert!(fp.fingerprint.ends_with("|m,p,s,a"), "{}", fp.fingerprint);
    }

    #[test]
    fn byte_by_byte_gives_same_result() {
        let (first, headers) = client_bytes();
        let mut all = first;
        all.extend_from_slice(&headers);
        let mut acc = AkamaiAccumulator::new(DEFAULT_ACCUMULATOR_LIMIT);
        let mut result = None;
        for b in &all {
            if let Ok(Some(fp)) = acc.push(std::slice::from_ref(b)) {
                result = Some(fp);
            }
        }
        assert_eq!(
            result.map(|f| f.fingerprint),
            extract_akamai_fingerprint_from_bytes(&all)
                .ok()
                .map(|f| f.fingerprint)
        );
    }

    #[test]
    fn rejects_non_http2_and_oversized_input() {
        let mut acc = AkamaiAccumulator::new(DEFAULT_ACCUMULATOR_LIMIT);
        assert_eq!(acc.push(b"GET / HTTP/1.1\r\n"), Err(AccumulatorError::NotHttp2));
        let mut small = AkamaiAccumulator::new(30);
        let (first, _) = client_bytes();
        assert_eq!(small.push(&first), Err(AccumulatorError::TooLarge));
        assert!(small.len() > 30);
    }
}
