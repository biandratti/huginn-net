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

/// Why a connection cannot produce an Akamai fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccumulatorError {
    /// The client bytes do not start with the HTTP/2 connection preface.
    NotHttp2,
    /// More than the configured limit was buffered without a complete HEADERS frame.
    TooLarge,
    /// HTTP/2 frames are present but the fingerprint fields are corrupt.
    Malformed,
}

pub struct AkamaiAccumulator {
    buf: Vec<u8>,
    limit: usize,
}

impl AkamaiAccumulator {
    pub fn new(limit: usize) -> Self {
        // A client preface, SETTINGS and the first HEADERS usually fit in 2 KiB.
        Self { buf: Vec::with_capacity(limit.min(2 * 1024)), limit }
    }

    /// Appends to the buffer. With `akamai-keylog` the buffer may hold decrypted bytes, so
    /// growth copies into a new allocation and wipes the old one instead of letting the
    /// allocator move it (which would leave an unwiped copy behind).
    fn append(&mut self, data: &[u8]) {
        #[cfg(feature = "akamai-keylog")]
        {
            let needed = self.buf.len().saturating_add(data.len());
            if needed > self.buf.capacity() {
                let mut grown =
                    Vec::with_capacity(needed.max(self.buf.capacity().saturating_mul(2)));
                grown.extend_from_slice(&self.buf);
                zeroize::Zeroize::zeroize(self.buf.as_mut_slice());
                self.buf = grown;
            }
        }
        self.buf.extend_from_slice(data);
    }

    /// Appends client bytes (starting at the HTTP/2 preface). Returns the fingerprint once the
    /// first client HEADERS frame is complete.
    pub fn push(&mut self, data: &[u8]) -> Result<Option<AkamaiFingerprint>, AccumulatorError> {
        self.append(data);
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
    #[cfg(feature = "akamai-keylog")]
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(feature = "akamai-keylog")]
impl Drop for AkamaiAccumulator {
    fn drop(&mut self) {
        // May hold decrypted application data. Only the filled part was ever written.
        zeroize::Zeroize::zeroize(self.buf.as_mut_slice());
    }
}
