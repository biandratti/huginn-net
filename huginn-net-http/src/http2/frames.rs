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

    /// Returns the total size of the frame in bytes (header + payload)
    ///
    /// HTTP/2 frames have a 9-byte header (3 bytes length + 1 byte type + 1 byte flags + 4 bytes stream ID)
    /// followed by the payload.
    ///
    /// # Returns
    /// The total size of the frame: 9 bytes (header) + payload length
    ///
    /// # Example
    /// ```no_run
    /// use huginn_net_http::Http2Frame;
    ///
    /// let frame = Http2Frame::new(0x4, 0x0, 0, vec![0x00, 0x03, 0x00, 0x00, 0x00, 0x64]);
    /// assert_eq!(frame.total_size(), 9 + 6); // 9 bytes header + 6 bytes payload
    /// ```
    #[must_use]
    pub fn total_size(&self) -> usize {
        9_usize.saturating_add(self.length as usize)
    }
}
