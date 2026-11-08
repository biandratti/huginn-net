use super::frames::{HTTP2_CONNECTION_PREFACE, Http2Frame, Http2FrameType};
use super::parser::Http2Parser;
use crate::akamai::AkamaiFingerprint;
use crate::akamai::extractor::extract_akamai_fingerprint;
use crate::error::HuginnNetHttpError;

/// HTTP/2 fingerprint extractor with incremental parsing support
///
/// This struct manages buffering, parsing, and fingerprint extraction for HTTP/2 connections,
/// handling incremental data arrival and connection preface automatically.
///
/// # Example
/// ```no_run
/// use huginn_net_http::http2_fingerprint_extractor::Http2FingerprintExtractor;
///
/// let mut extractor = Http2FingerprintExtractor::new();
///
/// // Add data as it arrives (preface, SETTINGS, ..., first HEADERS)
/// extractor.add_bytes(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
/// extractor.add_bytes(b"\x00\x00\x06\x04\x00\x00\x00\x00\x00");
///
/// // Ready once the first request HEADERS frame has arrived
/// if let Some(fingerprint) = extractor.get_fingerprint() {
///     println!("Akamai: {}", fingerprint.fingerprint);
/// }
/// ```
pub struct Http2FingerprintExtractor {
    parser: Http2Parser<'static>,
    buffer: Vec<u8>,
    parsed_offset: usize,
    /// Frames parsed so far: the fingerprint needs all of them, not only the last batch.
    frames: Vec<Http2Frame>,
    fingerprint: Option<AkamaiFingerprint>,
}

impl Http2FingerprintExtractor {
    /// Create a new HTTP/2 fingerprint extractor
    ///
    /// # Returns
    /// A new `Http2FingerprintExtractor` instance ready to process HTTP/2 data
    #[must_use]
    pub fn new() -> Self {
        Self {
            parser: Http2Parser::new(),
            buffer: Vec::with_capacity(64 * 1024),
            parsed_offset: 0,
            frames: Vec::new(),
            fingerprint: None,
        }
    }

    /// Add bytes to the buffer and attempt to extract fingerprint
    ///
    /// This method handles incremental data arrival, automatically skipping the HTTP/2
    /// connection preface and parsing frames as they become available.
    ///
    /// # Parameters
    /// - `data`: New bytes to add to the buffer
    ///
    /// # Returns
    /// - `Ok(Some(AkamaiFingerprint))` if fingerprint was successfully extracted
    /// - `Ok(None)` if more data is needed (the fingerprint is complete only once the first
    ///   request HEADERS frame has arrived, because it includes the pseudo-header order), or the
    ///   fingerprint was already extracted
    /// - `Err(MalformedPseudoHeaders)` if a HEADERS frame is present but its payload is corrupt
    /// - `Err(Parse)` if the raw bytes could not be parsed as HTTP/2 frames
    ///
    /// # Example
    /// ```no_run
    /// use huginn_net_http::http2_fingerprint_extractor::Http2FingerprintExtractor;
    ///
    /// let mut extractor = Http2FingerprintExtractor::new();
    /// match extractor.add_bytes(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x06\x04\x00\x00\x00\x00\x00") {
    ///     Ok(Some(fingerprint)) => println!("Got fingerprint: {}", fingerprint.fingerprint),
    ///     Ok(None) => println!("Need more data"),
    ///     Err(e) => eprintln!("Error: {e}"),
    /// }
    /// ```
    pub fn add_bytes(
        &mut self,
        data: &[u8],
    ) -> Result<Option<AkamaiFingerprint>, HuginnNetHttpError> {
        if self.fingerprint.is_some() {
            return Ok(None);
        }

        self.buffer.extend_from_slice(data);

        if self.parsed_offset == 0 {
            let preface = HTTP2_CONNECTION_PREFACE;
            if self.buffer.len() < preface.len() && preface.starts_with(&self.buffer) {
                return Ok(None); // the start of the preface
            }
            if self.buffer.starts_with(preface) {
                self.parsed_offset = preface.len();
            }
        }

        let frame_data = self.buffer.get(self.parsed_offset..).unwrap_or_default();
        if frame_data.len() < 9 {
            return Ok(None);
        }
        let (frames, bytes_consumed) = self
            .parser
            .parse_frames_with_offset(frame_data)
            .map_err(|e| HuginnNetHttpError::Parse(e.to_string()))?;
        self.parsed_offset = self.parsed_offset.saturating_add(bytes_consumed);
        self.frames.extend(frames);

        // SETTINGS, WINDOW_UPDATE and PRIORITY can arrive in separate reads; the HEADERS frame
        // that carries the pseudo-header order comes last.
        let has_headers = self
            .frames
            .iter()
            .any(|f| f.frame_type == Http2FrameType::Headers && f.stream_id != 0);
        if !has_headers {
            return Ok(None);
        }
        match extract_akamai_fingerprint(&self.frames) {
            Ok(fingerprint) => {
                self.fingerprint = Some(fingerprint.clone());
                Ok(Some(fingerprint))
            }
            Err(HuginnNetHttpError::NoSettingsFrame) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Get the extracted fingerprint if available
    ///
    /// # Returns
    /// - `Some(AkamaiFingerprint)` if fingerprint has been extracted
    /// - `None` if fingerprint not yet available
    #[must_use]
    pub fn get_fingerprint(&self) -> Option<&AkamaiFingerprint> {
        self.fingerprint.as_ref()
    }

    /// Check if fingerprint has been extracted
    ///
    /// # Returns
    /// `true` if fingerprint is available, `false` otherwise
    #[must_use]
    pub fn fingerprint_extracted(&self) -> bool {
        self.fingerprint.is_some()
    }

    /// Reset the extractor to process a new connection
    ///
    /// Clears the buffer and resets parsing state, allowing the extractor to be reused.
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.parsed_offset = 0;
        self.frames.clear();
        self.fingerprint = None;
    }
}

impl Default for Http2FingerprintExtractor {
    fn default() -> Self {
        Self::new()
    }
}
