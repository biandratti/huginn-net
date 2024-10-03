use pnet::packet::tcp::TcpOption;

/**
* sig = ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass
**/
#[derive(Debug)]
pub struct TcpSignature {
    pub ver: char,               // Version: '4', '6', or '*'
    pub ittl: u8,                // Initial TTL
    pub olen: u8,                // Length of IP options
    pub mss: Option<u16>,        // Maximum Segment Size
    pub wsize: String,           // Window size (can be fixed or a formula like "mss*4")
    pub scale: Option<u8>,       // Window scaling factor
    pub options: Vec<TcpOption>, // Layout of TCP options
    pub quirks: Vec<Quirk>,      // List of quirks
    pub pclass: PayloadClass,    // Payload size classification
}

#[derive(Debug)]
pub enum Quirk {
    Df,         // "Don't Fragment" flag set
    IdPlus,     // DF set, but non-zero IPID
    IdMinus,    // DF not set, zero IPID
    Ecn,        // Explicit Congestion Notification
    ZeroPlus,   // "Must be zero" field not zero
    Flow,       // Non-zero IPv6 flow ID
    SeqZero,    // Sequence number is zero
    AckPlus,    // ACK number non-zero, but ACK flag not set
    AckZero,    // ACK number is zero, but ACK flag set
    UrgPtrPlus, // URG pointer non-zero, but URG flag not set
    UrgFlag,    // URG flag used
    PushFlag,   // PUSH flag used
    Ts1Zero,    // Own timestamp specified as zero
    Ts2Plus,    // Peer timestamp non-zero on initial SYN
    OptPlus,    // Trailing non-zero data in options segment
    ExWscale,   // Excessive window scaling factor (> 14)
    BadOpt,     // Malformed TCP options
}

#[derive(Debug)]
pub enum PayloadClass {
    Zero,    // Zero payload
    NonZero, // Non-zero payload
    Any,     // Any payload
}

impl TcpSignature {
    pub fn all() -> Vec<TcpSignature> {
        vec![TcpSignature::linux_3_11_and_newer_v1()]
    }

    // *:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0
    fn linux_3_11_and_newer_v1() -> Self {
        Self {
            ver: '*',
            ittl: 64,
            olen: 0,
            mss: None,
            wsize: "mss*20".to_string(),
            scale: Some(10),
            options: vec![
                TcpOption::mss(1460),
                TcpOption::sack_perm(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::wscale(10),
            ],
            quirks: vec![Quirk::Df, Quirk::IdPlus],
            pclass: PayloadClass::Zero,
        }
    }
}
