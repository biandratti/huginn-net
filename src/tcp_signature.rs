use pnet::packet::tcp::TcpOption;
/**
For TCP traffic, signature layout is as follows:
sig = ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass
**/

#[derive(Debug)]
pub struct TcpSignature {
    pub mss: u16,

    pub ittl: u8,
    pub window: u16,
    /// TCP Options for SYN
    pub options: Vec<TcpOption>,
}

impl TcpSignature {
    // -------- SILLY --------

    pub fn nintendo_3ds() -> Self {
        // p0f fingerprint: *:64:0:1360:32768,0:mss,nop,nop,sok:df,id+:0
        Self {
            mss: 1360,
            ittl: 64,
            window: 32768,
            options: vec![
                TcpOption::mss(1360),
                TcpOption::nop(),
                TcpOption::nop(),
                TcpOption::sack_perm(),
            ],
        }
    }

    // -------- WINDOWS --------

    pub fn windows_xp() -> Self {
        // p0f fingerprint: *:128:0:*:16384,0:mss,nop,nop,sok:df,id+:0
        Self {
            mss: 1337,
            ittl: 128,
            window: 16384,
            options: vec![
                TcpOption::mss(1337),
                TcpOption::nop(),
                TcpOption::nop(),
                TcpOption::sack_perm(),
            ],
        }
    }

    pub fn windows_7_or_8() -> Self {
        // p0f fingerprint: *:128:0:*:8192,0:mss,nop,nop,sok:df,id+:0
        Self {
            mss: 1337,
            ittl: 128,
            window: 8192,
            options: vec![
                TcpOption::mss(1337),
                TcpOption::nop(),
                TcpOption::nop(),
                TcpOption::sack_perm(),
            ],
        }
    }

    // -------- LINUX/UNIX --------

    pub fn linux_3_11_and_newer_v1() -> Self {
        // sig: *:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0
        Self {
            mss: 128,
            ittl: 64,
            window: 128 * 20,
            options: vec![
                TcpOption::mss(128),
                TcpOption::sack_perm(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::wscale(10),
            ],
        }
    }
    pub fn linux_3_11_and_newer_v2() -> Self {
        // sig: *:64:0:*:mss*20,7:mss,sok,ts,nop,ws:df,id+:0
        Self {
            mss: 128,
            ittl: 64,
            window: 128 * 20,
            options: vec![
                TcpOption::mss(128),
                TcpOption::sack_perm(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::wscale(7),
            ],
        }
    }
    pub fn linux_3_1_3_10_v1() -> Self {
        // sig: *:64:0:*:mss*10,4:mss,sok,ts,nop,ws:df,id+:0
        Self {
            mss: 128,
            ittl: 64,
            window: 128 * 10,
            options: vec![
                TcpOption::mss(128),
                TcpOption::sack_perm(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::wscale(4),
            ],
        }
    }

    pub fn linux_3_1_3_10_v2() -> Self {
        // sig: *:64:0:*:mss*10,5:mss,sok,ts,nop,ws:df,id+:0
        Self {
            mss: 128,
            ittl: 64,
            window: 128 * 10,
            options: vec![
                TcpOption::mss(128),
                TcpOption::sack_perm(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::wscale(5),
            ],
        }
    }

    pub fn linux_3_1_3_10_v3() -> Self {
        // sig: *:64:0:*:mss*10,6:mss,sok,ts,nop,ws:df,id+:0
        Self {
            mss: 128,
            ittl: 64,
            window: 128 * 10,
            options: vec![
                TcpOption::mss(128),
                TcpOption::sack_perm(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::wscale(6),
            ],
        }
    }

    pub fn linux_3_1_3_10_v4() -> Self {
        // sig: *:64:0:*:mss*10,7:mss,sok,ts,nop,ws:df,id+:0
        Self {
            mss: 128,
            ittl: 64,
            window: 128 * 10,
            options: vec![
                TcpOption::mss(128),
                TcpOption::sack_perm(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::wscale(7),
            ],
        }
    }

    pub fn linux_2_6_x_v1() -> Self {
        // sig: *:64:0:*:mss*4,6:mss,sok,ts,nop,ws:df,id+:0
        Self {
            mss: 128,
            ittl: 64,
            window: 128 * 4,
            options: vec![
                TcpOption::mss(128),
                TcpOption::sack_perm(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::wscale(6),
            ],
        }
    }

    pub fn linux_2_6_x_v2() -> Self {
        // sig: *:64:0:*:mss*4,7:mss,sok,ts,nop,ws:df,id+:0
        Self {
            mss: 128,
            ittl: 64,
            window: 128 * 4,
            options: vec![
                TcpOption::mss(128),
                TcpOption::sack_perm(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::wscale(7),
            ],
        }
    }

    pub fn linux_2_6_x_v3() -> Self {
        // sig: *:64:0:*:mss*4,8:mss,sok,ts,nop,ws:df,id+:0
        Self {
            mss: 128,
            ittl: 64,
            window: 128 * 4,
            options: vec![
                TcpOption::mss(128),
                TcpOption::sack_perm(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::wscale(8),
            ],
        }
    }

    pub fn linux_2_4_x_v1() -> Self {
        // sig: *:64:0:*:mss*4,0:mss,sok,ts,nop,ws:df,id+:0
        Self {
            mss: 128,
            ittl: 64,
            window: 128 * 4,
            options: vec![
                TcpOption::mss(128),
                TcpOption::sack_perm(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::wscale(0),
            ],
        }
    }

    pub fn linux_2_4_x_v2() -> Self {
        // sig: *:64:0:*:mss*4,1:mss,sok,ts,nop,ws:df,id+:0
        Self {
            mss: 128,
            ittl: 64,
            window: 128 * 4,
            options: vec![
                TcpOption::mss(128),
                TcpOption::sack_perm(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::wscale(1),
            ],
        }
    }

    pub fn linux_2_4_x_v3() -> Self {
        // sig: *:64:0:*:mss*4,2:mss,sok,ts,nop,ws:df,id+:0
        Self {
            mss: 128,
            ittl: 64,
            window: 128 * 4,
            options: vec![
                TcpOption::mss(128),
                TcpOption::sack_perm(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::wscale(2),
            ],
        }
    }

    pub fn linux_2_2_x_v1() -> Self {
        // sig: *:64:0:*:mss*11,0:mss,sok,ts,nop,ws:df,id+:0
        Self {
            mss: 128,
            ittl: 64,
            window: 128 * 11,
            options: vec![
                TcpOption::mss(128),
                TcpOption::sack_perm(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::wscale(0),
            ],
        }
    }

    pub fn linux_2_2_x_v2() -> Self {
        // sig: *:64:0:*:mss*20,0:mss,sok,ts,nop,ws:df,id+:0
        Self {
            mss: 128,
            ittl: 64,
            window: 128 * 20,
            options: vec![
                TcpOption::mss(128),
                TcpOption::sack_perm(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::wscale(0),
            ],
        }
    }

    pub fn linux_2_2_x_v3() -> Self {
        // sig: *:64:0:*:mss*20,0:mss,sok,ts,nop,ws:df,id+:0
        Self {
            mss: 128,
            ittl: 64,
            window: 128 * 22,
            options: vec![
                TcpOption::mss(128),
                TcpOption::sack_perm(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::wscale(0),
            ],
        }
    }

    pub fn linux_2_0_v1() -> Self {
        // sig: *:64:0:*:mss*12,0:mss::0
        Self {
            mss: 128,
            ittl: 64,
            window: 128 * 12,
            options: vec![TcpOption::mss(128)],
        }
    }

    pub fn linux_2_0_v2() -> Self {
        // sig: *:64:0:*:16384,0:mss::0
        Self {
            mss: 128,
            ittl: 64,
            window: 16384,
            options: vec![TcpOption::mss(128)],
        }
    }

    pub fn linux_3_x_loopback_v1() -> Self {
        // sig: *:64:0:16396:mss*2,4:mss,sok,ts,nop,ws:df,id+:0
        Self {
            mss: 128,
            ittl: 64,
            window: 16396,
            options: vec![
                TcpOption::mss(128),
                TcpOption::sack_perm(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::wscale(4),
            ],
        }
    }

    pub fn linux_3_x_loopback_v2() -> Self {
        // sig: *:64:0:16376:mss*2,4:mss,sok,ts,nop,ws:df,id+:0
        Self {
            mss: 128,
            ittl: 64,
            window: 16376,
            options: vec![
                TcpOption::mss(128),
                TcpOption::sack_perm(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::wscale(4),
            ],
        }
    }

    pub fn linux_2_6_x_loopback_v1() -> Self {
        // sig: *:64:0:16396:mss*2,2:mss,sok,ts,nop,ws:df,id+:0
        Self {
            mss: 128,
            ittl: 64,
            window: 16396,
            options: vec![
                TcpOption::mss(128),
                TcpOption::sack_perm(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::wscale(4),
            ],
        }
    }

    pub fn linux_2_6_x_loopback_v2() -> Self {
        // sig: *:64:0:16376:mss*2,2:mss,sok,ts,nop,ws:df,id+:0
        Self {
            mss: 128,
            ittl: 64,
            window: 16376,
            options: vec![
                TcpOption::mss(128),
                TcpOption::sack_perm(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::wscale(4),
            ],
        }
    }

    pub fn linux_2_4_x_loopback() -> Self {
        // sig: *:64:0:16396:mss*2,0:mss,sok,ts,nop,ws:df,id+:0
        Self {
            mss: 128,
            ittl: 64,
            window: 16396,
            options: vec![
                TcpOption::mss(128),
                TcpOption::sack_perm(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::wscale(0),
            ],
        }
    }

    pub fn linux_2_2_x_loopback() -> Self {
        // sig: *:64:0:3884:mss*8,0:mss,sok,ts,nop,ws:df,id+:0
        Self {
            mss: 128,
            ittl: 64,
            window: 3884,
            options: vec![
                TcpOption::mss(128),
                TcpOption::sack_perm(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::wscale(0),
            ],
        }
    }

    pub fn solaris_8() -> Self {
        // p0f fingerprint: *:64:0:*:32850,1:nop,ws,nop,nop,ts,nop,nop,sok,mss:df,id+:0
        Self {
            mss: 1337,
            ittl: 64,
            window: 32850,
            options: vec![
                TcpOption::nop(),
                TcpOption::wscale(1),
                TcpOption::nop(),
                TcpOption::nop(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::nop(),
                TcpOption::sack_perm(),
                TcpOption::mss(1337),
            ],
        }
    }

    // p0f fingerprint: *:64:0:*:mss*44,1:mss,sok,ts,nop,ws:df,id+:0
    pub fn android() -> Self {
        Self {
            mss: 1000,
            ittl: 64,
            window: 1000 * 44,
            options: vec![
                TcpOption::mss(1000),
                TcpOption::sack_perm(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::wscale(1),
            ],
        }
    }
}
