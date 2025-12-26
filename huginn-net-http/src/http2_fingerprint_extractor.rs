use crate::akamai::AkamaiFingerprint;
use crate::akamai_extractor::extract_akamai_fingerprint;
use crate::http2_parser::{Http2ParseError, Http2Parser, HTTP2_CONNECTION_PREFACE};

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
/// // Add data incrementally
/// extractor.add_bytes(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
/// extractor.add_bytes(b"\x00\x00\x06\x04\x00\x00\x00\x00\x00");
///
/// // Check if fingerprint is ready
/// if let Some(fingerprint) = extractor.get_fingerprint() {
///     println!("Akamai: {}", fingerprint.fingerprint);
/// }
/// ```
pub struct Http2FingerprintExtractor {
    parser: Http2Parser<'static>,
    buffer: Vec<u8>,
    parsed_offset: usize,
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
    /// - `Ok(None)` if more data is needed or fingerprint already extracted
    /// - `Err(Http2ParseError)` if parsing fails
    ///
    /// # Example
    /// ```no_run
    /// use huginn_net_http::http2_fingerprint_extractor::Http2FingerprintExtractor;
    ///
    /// let mut extractor = Http2FingerprintExtractor::new();
    /// match extractor.add_bytes(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x06\x04\x00\x00\x00\x00\x00") {
    ///     Ok(Some(fingerprint)) => println!("Got fingerprint: {}", fingerprint.fingerprint),
    ///     Ok(None) => println!("Need more data"),
    ///     Err(e) => eprintln!("Error: {:?}", e),
    /// }
    /// ```
    pub fn add_bytes(&mut self, data: &[u8]) -> Result<Option<AkamaiFingerprint>, Http2ParseError> {
        // If fingerprint already extracted, don't process more data
        if self.fingerprint.is_some() {
            return Ok(None);
        }

        self.buffer.extend_from_slice(data);

        // Skip HTTP/2 connection preface
        let start_offset =
            if self.parsed_offset == 0 && self.buffer.starts_with(HTTP2_CONNECTION_PREFACE) {
                HTTP2_CONNECTION_PREFACE.len()
            } else {
                self.parsed_offset
            };

        let frame_data = &self.buffer[start_offset..];

        if frame_data.len() >= 9 {
            match self.parser.parse_frames_with_offset(frame_data) {
                Ok((frames, bytes_consumed)) => {
                    if !frames.is_empty() {
                        // Update parsed_offset based on actual bytes consumed
                        self.parsed_offset = start_offset.saturating_add(bytes_consumed);

                        if let Some(fingerprint) = extract_akamai_fingerprint(&frames) {
                            self.fingerprint = Some(fingerprint.clone());
                            return Ok(Some(fingerprint));
                        }
                    }
                }
                Err(e) => {
                    // Parsing error, might need more data
                    return Err(e);
                }
            }
        }

        Ok(None)
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
        self.fingerprint = None;
    }
}

impl Default for Http2FingerprintExtractor {
    fn default() -> Self {
        Self::new()
    }
}
