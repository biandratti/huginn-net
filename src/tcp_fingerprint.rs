#[derive(Debug)]
pub struct TcpFingerprint {
    pub ittl: u8,
    pub mss: u16,
    pub window: u32,
    pub options: Vec<TcpOption>,
}

#[derive(Debug, PartialEq)]
pub enum TcpOption {
    Mss(u16),
    Nop,
    SackPermitted,
    Timestamp(u32, u32),
    WindowScale(u8),
}

impl TcpFingerprint {
    pub fn linux_3_11_and_newer() -> Self {
        Self {
            mss: 1460,
            ittl: 64,
            window: 5840,
            options: vec![
                TcpOption::Mss(1460),
                TcpOption::SackPermitted,
                TcpOption::Timestamp(1, 0),
                TcpOption::Nop,
                TcpOption::WindowScale(7),
            ],
        }
    }

    pub fn windows_xp() -> Self {
        Self {
            mss: 1460,
            ittl: 128,
            window: 8192,
            options: vec![
                TcpOption::Mss(1460),
                TcpOption::Nop,
                TcpOption::Nop,
                TcpOption::SackPermitted,
            ],
        }
    }
}
