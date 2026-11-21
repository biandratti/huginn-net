mod parser;
mod process;

#[cfg(feature = "akamai")]
mod fingerprint;

/// Helper function to create an HTTP/2 frame
///
/// Creates a valid HTTP/2 frame with the specified type, stream ID, and payload.
/// Frame format: [length:24][type:8][flags:8][stream_id:32][payload]
fn create_http2_frame(frame_type: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();

    // Length (24 bits, big-endian)
    let length = payload.len() as u32;
    frame.push(((length >> 16) & 0xFF) as u8);
    frame.push(((length >> 8) & 0xFF) as u8);
    frame.push((length & 0xFF) as u8);

    // Type (8 bits)
    frame.push(frame_type);

    // Flags (8 bits)
    frame.push(0x00);

    // Stream ID (32 bits, big-endian, with reserved bit cleared)
    frame.extend_from_slice(&(stream_id & 0x7FFF_FFFF).to_be_bytes());

    // Payload
    frame.extend_from_slice(payload);

    frame
}
