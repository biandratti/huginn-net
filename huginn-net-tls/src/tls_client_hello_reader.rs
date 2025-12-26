use crate::tls::Signature;
use crate::tls_process::parse_tls_client_hello;

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
        // If signature already parsed, don't process more data
        if self.signature.is_some() {
            return Ok(None);
        }

        // Check if we have enough data to determine TLS record length
        self.buffer.extend_from_slice(data);

        // Need at least 5 bytes to read TLS record header
        if self.buffer.len() < 5 {
            return Ok(None);
        }

        // Read TLS record length from bytes 3-4
        let record_len = u16::from_be_bytes([self.buffer[3], self.buffer[4]]) as usize;
        let needed = record_len.saturating_add(5);

        // Check if we have complete TLS record
        if self.buffer.len() < needed {
            return Ok(None);
        }

        // Safety limit: don't process records larger than 64KB
        if needed > 64 * 1024 {
            return Err(crate::error::HuginnNetTlsError::Parse("TLS record too large".to_string()));
        }

        // Parse ClientHello
        match parse_tls_client_hello(&self.buffer[..needed]) {
            Ok(signature) => {
                self.signature = Some(signature.clone());
                Ok(Some(signature))
            }
            Err(e) => Err(e),
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
}

impl Default for TlsClientHelloReader {
    fn default() -> Self {
        Self::new()
    }
}
