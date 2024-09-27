/**
For TCP traffic, signature layout is as follows:
sig = ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass
**/

#[derive(Debug)]
pub struct TcpSignature {
    pub(crate) mss: Option<u16>,
    pub(crate) ttl: u8,
    pub(crate) window: Option<u16>,
    pub(crate) df: bool,
    pub(crate) options: Vec<TcpOption>,
    quirks: String,
}

#[derive(Debug, PartialEq)]
pub enum TcpOption {
    Mss(u16),
    SackPermitted,
    Timestamp(u32, u32),
    Nop,
    WindowScale(u8),
}

impl TcpSignature {
    pub fn new(mss: Option<u16>, ttl: u8, window: Option<u16>, df: bool, options: Vec<TcpOption>, quirks: String) -> Self {
        Self {
            mss,
            ttl,
            window,
            df,
            options,
            quirks,
        }
    }

    pub fn linux_3_11_and_newer() -> Vec<Self> {
        vec![
            Self::new(Some(1460), 64, None, true, vec![
                TcpOption::Mss(1460),
                TcpOption::SackPermitted,
                TcpOption::Timestamp(0, 0),
                TcpOption::Nop,
                TcpOption::WindowScale(7),
            ], "id+".to_string()),


            Self::new(Some(1460), 64, None, true, vec![
                TcpOption::Mss(1460),
                TcpOption::SackPermitted,
                TcpOption::Timestamp(0, 0),
                TcpOption::Nop,
                TcpOption::WindowScale(6),
            ], "id+".to_string()),
        ]
    }

    pub fn linux_2_6_x() -> Vec<Self> {
        vec![
            Self::new(Some(1460), 64, None, true, vec![
                TcpOption::Mss(1460),
                TcpOption::SackPermitted,
                TcpOption::Timestamp(0, 0),
                TcpOption::Nop,
                TcpOption::WindowScale(7),
            ], "id+".to_string()),

        ]
    }

}
