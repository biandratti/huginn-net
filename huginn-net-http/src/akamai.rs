use std::fmt;

/// HTTP/2 Setting parameter ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SettingId {
    HeaderTableSize = 1,
    EnablePush = 2,
    MaxConcurrentStreams = 3,
    InitialWindowSize = 4,
    MaxFrameSize = 5,
    MaxHeaderListSize = 6,
    NoRfc7540Priorities = 9,
    Unknown(u16),
}

impl From<u16> for SettingId {
    fn from(id: u16) -> Self {
        match id {
            1 => Self::HeaderTableSize,
            2 => Self::EnablePush,
            3 => Self::MaxConcurrentStreams,
            4 => Self::InitialWindowSize,
            5 => Self::MaxFrameSize,
            6 => Self::MaxHeaderListSize,
            9 => Self::NoRfc7540Priorities,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for SettingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderTableSize => write!(f, "HEADER_TABLE_SIZE"),
            Self::EnablePush => write!(f, "ENABLE_PUSH"),
            Self::MaxConcurrentStreams => write!(f, "MAX_CONCURRENT_STREAMS"),
            Self::InitialWindowSize => write!(f, "INITIAL_WINDOW_SIZE"),
            Self::MaxFrameSize => write!(f, "MAX_FRAME_SIZE"),
            Self::MaxHeaderListSize => write!(f, "MAX_HEADER_LIST_SIZE"),
            Self::NoRfc7540Priorities => write!(f, "NO_RFC7540_PRIORITIES"),
            Self::Unknown(id) => write!(f, "UNKNOWN_{id}"),
        }
    }
}

impl SettingId {
    /// Convert to numeric ID for fingerprint generation
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::HeaderTableSize => 1,
            Self::EnablePush => 2,
            Self::MaxConcurrentStreams => 3,
            Self::InitialWindowSize => 4,
            Self::MaxFrameSize => 5,
            Self::MaxHeaderListSize => 6,
            Self::NoRfc7540Priorities => 9,
            Self::Unknown(id) => id,
        }
    }
}

/// HTTP/2 Setting parameter (ID and value)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingParameter {
    pub id: SettingId,
    pub value: u32,
}

impl fmt::Display for SettingParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.id, self.value)
    }
}

/// HTTP/2 Priority information
///
/// Weight in HTTP/2 spec is 0-255, but represents 1-256 (add 1 to value)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http2Priority {
    pub stream_id: u32,
    pub exclusive: bool,
    pub depends_on: u32,
    pub weight: u8, // 0-255 in frame, represents 1-256
}

impl fmt::Display for Http2Priority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "stream={}, exclusive={}, depends_on={}, weight={}",
            self.stream_id,
            self.exclusive,
            self.depends_on,
            self.weight.saturating_add(1) // Display as 1-256
        )
    }
}

/// Pseudo-header order in HTTP/2 HEADERS frame
///
/// Common orders:
/// - Chrome: :method, :path, :authority, :scheme
/// - Firefox: :method, :path, :authority, :scheme
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PseudoHeader {
    Method,
    Path,
    Authority,
    Scheme,
    Status,
    Unknown(String),
}

impl From<&str> for PseudoHeader {
    fn from(s: &str) -> Self {
        match s {
            ":method" => Self::Method,
            ":path" => Self::Path,
            ":authority" => Self::Authority,
            ":scheme" => Self::Scheme,
            ":status" => Self::Status,
            other => Self::Unknown(other.to_string()),
        }
    }
}

impl fmt::Display for PseudoHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Method => write!(f, "m"),
            Self::Path => write!(f, "p"),
            Self::Authority => write!(f, "a"),
            Self::Scheme => write!(f, "s"),
            Self::Status => write!(f, "st"),
            Self::Unknown(name) => write!(f, "?{name}"),
        }
    }
}

/// Akamai HTTP/2 Fingerprint
///
/// Based on: https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf
///
/// Format: `S[;]|WU|P[,]|PS[,]`
/// - S: Settings parameters (id:value;...)
/// - WU: Window Update value
/// - P: Priority frames (stream:exclusive:depends_on:weight,...)
/// - PS: Pseudo-header order (m,p,a,s)
///
/// Example: `1:65536;2:0;3:1000;4:6291456;5:16384;6:262144|15663105|0|m,p,a,s`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AkamaiFingerprint {
    /// SETTINGS frame parameters (order matters)
    pub settings: Vec<SettingParameter>,
    /// WINDOW_UPDATE initial value
    pub window_update: u32,
    /// PRIORITY frames
    pub priority_frames: Vec<Http2Priority>,
    /// Pseudo-header order from HEADERS frame
    pub pseudo_header_order: Vec<PseudoHeader>,
    /// Fingerprint string representation
    pub fingerprint: String,
    /// Hash of the fingerprint (for database lookup)
    pub hash: String,
}

impl AkamaiFingerprint {
    /// Generate the Akamai fingerprint string
    ///
    /// Format: `settings|window_update|priorities|pseudo_headers`
    #[must_use]
    pub fn generate_fingerprint_string(
        settings: &[SettingParameter],
        window_update: u32,
        priority_frames: &[Http2Priority],
        pseudo_header_order: &[PseudoHeader],
    ) -> String {
        // Settings: id:value;id:value;...
        let settings_str = if settings.is_empty() {
            String::new()
        } else {
            settings
                .iter()
                .map(|s| format!("{}:{}", s.id.as_u16(), s.value))
                .collect::<Vec<_>>()
                .join(";")
        };

        // Window Update: value or "00" if not present
        let window_str = if window_update == 0 {
            "00".to_string()
        } else {
            window_update.to_string()
        };

        // Priority: stream:exclusive:depends_on:weight,...
        let priority_str = if priority_frames.is_empty() {
            "0".to_string()
        } else {
            priority_frames
                .iter()
                .map(|p| {
                    format!(
                        "{}:{}:{}:{}",
                        p.stream_id,
                        u8::from(p.exclusive),
                        p.depends_on,
                        u16::from(p.weight).saturating_add(1) // Weight is 1-256, RFC 7540 says byte+1
                    )
                })
                .collect::<Vec<_>>()
                .join(",")
        };

        // Pseudo-headers: m,p,a,s
        let pseudo_str = pseudo_header_order
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");

        format!("{settings_str}|{window_str}|{priority_str}|{pseudo_str}")
    }

    /// Create a new Akamai fingerprint
    ///
    /// # Parameters
    /// - `settings`: SETTINGS frame parameters
    /// - `window_update`: WINDOW_UPDATE value
    /// - `priority_frames`: PRIORITY frames
    /// - `pseudo_header_order`: Pseudo-header order from HEADERS frame
    #[must_use]
    pub fn new(
        settings: Vec<SettingParameter>,
        window_update: u32,
        priority_frames: Vec<Http2Priority>,
        pseudo_header_order: Vec<PseudoHeader>,
    ) -> Self {
        let fingerprint = Self::generate_fingerprint_string(
            &settings,
            window_update,
            &priority_frames,
            &pseudo_header_order,
        );

        let hash = Self::hash_fingerprint(&fingerprint);

        Self { settings, window_update, priority_frames, pseudo_header_order, fingerprint, hash }
    }

    /// Hash the fingerprint for database lookup (SHA-256 truncated)
    #[must_use]
    pub fn hash_fingerprint(fingerprint: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(fingerprint.as_bytes());
        let result = hasher.finalize();
        // Truncate to first 16 bytes (32 hex chars) like JA3
        format!("{result:x}").chars().take(32).collect::<String>()
    }
}

impl fmt::Display for AkamaiFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Akamai HTTP/2 Fingerprint:")?;
        writeln!(f, "  Fingerprint: {}", self.fingerprint)?;
        writeln!(f, "  Hash:        {}", self.hash)?;
        writeln!(f)?;
        writeln!(f, "  SETTINGS:")?;
        for setting in &self.settings {
            writeln!(f, "    {setting}")?;
        }
        writeln!(f)?;
        writeln!(f, "  WINDOW_UPDATE: {}", self.window_update)?;
        writeln!(f)?;
        if self.priority_frames.is_empty() {
            writeln!(f, "  PRIORITY: none")?;
        } else {
            writeln!(f, "  PRIORITY:")?;
            for priority in &self.priority_frames {
                writeln!(f, "    {priority}")?;
            }
        }
        writeln!(f)?;
        writeln!(
            f,
            "  Pseudo-headers: {}",
            self.pseudo_header_order
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}
