use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/**
* sig = ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass
**/
#[derive(Debug)]
pub struct TcpSignature {
    pub ver: IpVersion,
    pub ittl: TTL,
    pub olen: u8,
    pub mss: Option<u16>,
    pub wsize: WindowSize,
    pub scale: Option<u8>,
    pub options: Vec<TcpOption>,
    pub quirks: Vec<Quirk>,
    pub pclass: PayloadSize,
}

#[derive(Clone, Debug, PartialEq)]
pub enum IpVersion {
    V4,
    V6,
    Any,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TTL {
    Value(u8),
    Distance(u8, u8),
    Guess(u8),
    Bad(u8),
}

#[derive(Clone, Debug, PartialEq)]
pub enum WindowSize {
    MSS(u8),
    MTU(u8),
    Value(u16),
    Mod(u16),
    Any,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TcpOption {
    /// eol+n  - explicit end of options, followed by n bytes of padding
    EOL(u8),
    /// nop    - no-op option
    NOP,
    /// mss    - maximum segment size
    MSS,
    /// ws     - window scaling
    WS,
    /// sok    - selective ACK permitted
    SOK,
    /// sack   - selective ACK (should not be seen)
    SACK,
    /// ts     - timestamp
    TS,
    /// ?n     - unknown option ID n
    Unknown(u8),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Quirk {
    /// df     - "don't fragment" set (probably PMTUD); ignored for IPv6
    DF,
    /// id+    - DF set but IPID non-zero; ignored for IPv6
    NonZeroID,
    /// id-    - DF not set but IPID is zero; ignored for IPv6
    ZeroID,
    /// ecn    - explicit congestion notification support
    ECN,
    /// 0+     - "must be zero" field not zero; ignored for IPv6
    MustBeZero,
    /// flow   - non-zero IPv6 flow ID; ignored for IPv4
    FlowID,
    /// seq-   - sequence number is zero
    SeqNumZero,
    /// ack+   - ACK number is non-zero, but ACK flag not set
    AckNumNonZero,
    /// ack-   - ACK number is zero, but ACK flag set
    AckNumZero,
    /// uptr+  - URG pointer is non-zero, but URG flag not set
    NonZeroURG,
    /// urgf+  - URG flag used
    URG,
    /// pushf+ - PUSH flag used
    PUSH,
    /// ts1-   - own timestamp specified as zero
    OwnTimestampZero,
    /// ts2+   - non-zero peer timestamp on initial SYN
    PeerTimestampNonZero,
    /// opt+   - trailing non-zero data in options segment
    TrailinigNonZero,
    /// exws   - excessive window scaling factor (> 14)
    ExcessiveWindowScaling,
    /// bad    - malformed TCP options
    OptBad,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PayloadSize {
    Zero,
    NonZero,
    Any,
}

impl TcpSignature {
    pub fn all() -> Vec<TcpSignature> {
        let path = Path::new("config/p0f.fp");

        let file = File::open(path).expect("Failed to open file");
        let reader = BufReader::new(file);

        let mut tcp_signatures = Vec::new();

        for line in reader.lines() {
            let line = line.expect("Failed to read line");
            if line.trim().is_empty() {
                continue; // Skip empty lines
            }

        }

        tcp_signatures
    }
}



