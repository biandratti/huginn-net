use crate::tls::Signature;
use crate::tls_process::parse_tls_client_hello;
use tracing::{debug, error};

/// TLS ClientHello reader with incremental parsing support
///
/// This struct manages reading and parsing TLS ClientHello messages incrementally,
/// handling cases where the ClientHello arrives in multiple TCP packets.
///
/// # Example
/// ```no_run
/// use huginn_net_tls::tls_client_hello_reader::TlsClientHelloReader;
///
/// let mut reader = TlsClientHelloReader::new();
///
/// // Add bytes incrementally
/// reader.add_bytes(&[0x16, 0x03, 0x01, 0x00, 0x4a]);
/// reader.add_bytes(&[/* more bytes */]);
///
/// if let Some(signature) = reader.get_signature() {
///     println!("Got TLS signature");
/// }
/// ```
pub struct TlsClientHelloReader {
    buffer: Vec<u8>,
    signature: Option<Signature>,
}

impl TlsClientHelloReader {
    /// Create a new TLS ClientHello reader
    ///
    /// # Returns
    /// A new `TlsClientHelloReader` instance ready to process TLS ClientHello data
    #[must_use]
    pub fn new() -> Self {
        Self { buffer: Vec::with_capacity(8192), signature: None }
    }

    /// Add bytes to the buffer and attempt to parse ClientHello
    ///
    /// This method handles incremental data arrival, parsing the ClientHello as soon
    /// as enough data is available.
    ///
    /// # Parameters
    /// - `data`: New bytes to add to the buffer
    ///
    /// # Returns
    /// - `Ok(Some(Signature))` if ClientHello was successfully parsed
    /// - `Ok(None)` if more data is needed or signature already parsed
    /// - `Err(HuginnNetTlsError)` if parsing fails
    pub fn add_bytes(
        &mut self,
        data: &[u8],
    ) -> Result<Option<Signature>, crate::error::HuginnNetTlsError> {
        if self.signature.is_some() {
            debug!("Signature already parsed, skipping new bytes.");
            return Ok(None);
        }

        // Check if we have enough data to determine TLS record length
        self.buffer.extend_from_slice(data);

        if self.buffer.len() < 5 {
            debug!("Not enough bytes for TLS record header (have {}, need 5)", self.buffer.len());
            return Ok(None);
        }

        let content_type = self.buffer[0];
        // Skip version bytes (buffer[1] and buffer[2]) - not needed for length calculation
        let record_len = u16::from_be_bytes([self.buffer[3], self.buffer[4]]) as usize;
        let needed = record_len.saturating_add(5); // 5 bytes for header + record_len

        // Check if it's a TLS handshake record (0x16)
        if content_type != 0x16 {
            debug!("First byte is not TLS Handshake (0x16), got 0x{:02x}. Might be continuation data.", content_type);
            return Ok(None);
        }

        // Check if we have complete TLS record
        if self.buffer.len() < needed {
            debug!("Incomplete TLS record: have {} bytes, need {} bytes. Accumulating...", 
                   self.buffer.len(), needed);
            return Ok(None);
        }

        // Safety limit: don't process records larger than 64KB
        if needed > 64 * 1024 {
            error!("TLS record too large ({} bytes), resetting buffer.", needed);
            self.reset(); // Clear buffer to avoid processing malicious large records
            return Err(crate::error::HuginnNetTlsError::Parse("TLS record too large".to_string()));
        }

        debug!("Complete TLS record detected: record_len={}, total_available={}", 
              record_len, self.buffer.len());

        // Parse ClientHello
        match parse_tls_client_hello(&self.buffer[..needed]) {
            Ok(signature) => {
                debug!("Successfully parsed TLS ClientHello from reassembled buffer");
                self.signature = Some(signature.clone());
                // Clear buffer after successful parse to prepare for next ClientHello
                self.buffer.drain(..needed);
                Ok(Some(signature))
            }
            Err(e) => {
                error!("Failed to parse TLS ClientHello from reassembled buffer: {:?}", e);
                debug!("Buffer (first 200 bytes): {:02x?}", 
                       self.buffer.get(0..200.min(needed)).map(|s| s.to_vec()).unwrap_or_default());
                // Don't reset on error - might be a parsing issue we can debug
                Err(e)
            }
        }
    }

    /// Get the parsed signature if available
    ///
    /// # Returns
    /// - `Some(Signature)` if signature has been parsed
    /// - `None` if signature not yet available
    #[must_use]
    pub fn get_signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }

    /// Check if signature has been parsed
    ///
    /// # Returns
    /// `true` if signature is available, `false` otherwise
    #[must_use]
    pub fn signature_parsed(&self) -> bool {
        self.signature.is_some()
    }

    /// Reset the reader to process a new ClientHello
    ///
    /// Clears the buffer and resets parsing state, allowing the reader to be reused.
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.signature = None;
    }

    /// Get the current buffer size
    ///
    /// Returns the number of bytes currently accumulated in the buffer.
    #[must_use]
    pub fn buffer_len(&self) -> usize {
        self.buffer.len()
    }
}

impl Default for TlsClientHelloReader {
    fn default() -> Self {
        Self::new()
    }
}
