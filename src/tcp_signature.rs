use pnet::packet::tcp::TcpOption;

#[derive(Debug)]
pub struct TcpSignature {
    pub mss: u16,
    pub ittl: u8,
    pub window: u16,
    pub options: Vec<TcpOption>,
    pub sig: String,
}

impl TcpSignature {
    pub fn all() -> Vec<TcpSignature> {
        vec![
            TcpSignature::nintendo_3ds(),
            TcpSignature::windows_xp(),
            TcpSignature::windows_7_or_8(),
            TcpSignature::linux_3_11_and_newer_v1(),
            TcpSignature::linux_3_11_and_newer_v2(),
            TcpSignature::linux_3_1_3_10_v1(),
            TcpSignature::linux_3_1_3_10_v2(),
            TcpSignature::linux_3_1_3_10_v3(),
            TcpSignature::linux_3_1_3_10_v4(),
            TcpSignature::linux_2_6_x_v1(),
            TcpSignature::linux_2_6_x_v2(),
            TcpSignature::linux_2_6_x_v3(),
            TcpSignature::linux_2_4_x_v1(),
            TcpSignature::linux_2_4_x_v2(),
            TcpSignature::linux_2_4_x_v3(),
            TcpSignature::linux_2_2_x_v1(),
            TcpSignature::linux_2_2_x_v2(),
            TcpSignature::linux_2_2_x_v3(),
            TcpSignature::linux_2_0_v1(),
            TcpSignature::linux_2_0_v2(),
            TcpSignature::linux_3_x_loopback_v1(),
            TcpSignature::linux_3_x_loopback_v2(),
            TcpSignature::linux_2_6_x_loopback_v1(),
            TcpSignature::linux_2_6_x_loopback_v2(),
            TcpSignature::linux_2_4_x_loopback(),
            TcpSignature::linux_2_2_x_loopback(),
            TcpSignature::solaris_8(),
            TcpSignature::android(),
        ]
    }
    // -------- SILLY --------

    fn nintendo_3ds() -> Self {
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
            sig: "*:64:0:1360:32768,0:mss,nop,nop,sok:df,id+:0".to_string(),
        }
    }

    // -------- WINDOWS --------

    fn windows_xp() -> Self {
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
            sig: "*:128:0:*:16384,0:mss,nop,nop,sok:df,id+:0".to_string(),
        }
    }

    fn windows_7_or_8() -> Self {
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
            sig: "*:128:0:*:8192,0:mss,nop,nop,sok:df,id+:0".to_string(),
        }
    }

    // -------- LINUX/UNIX --------

    fn linux_3_11_and_newer_v1() -> Self {
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
            sig: "*:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        }
    }
    fn linux_3_11_and_newer_v2() -> Self {
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
            sig: "*:64:0:*:mss*20,7:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        }
    }
    fn linux_3_1_3_10_v1() -> Self {
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
            sig: "*:64:0:*:mss*10,4:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        }
    }

    fn linux_3_1_3_10_v2() -> Self {
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
            sig: "*:64:0:*:mss*10,5:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        }
    }

    fn linux_3_1_3_10_v3() -> Self {
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
            sig: "*:64:0:*:mss*10,6:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        }
    }

    fn linux_3_1_3_10_v4() -> Self {
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
            sig: "*:64:0:*:mss*10,7:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        }
    }

    fn linux_2_6_x_v1() -> Self {
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
            sig: "*:64:0:*:mss*4,6:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        }
    }

    fn linux_2_6_x_v2() -> Self {
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
            sig: "*:64:0:*:mss*4,7:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        }
    }

    fn linux_2_6_x_v3() -> Self {
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
            sig: "*:64:0:*:mss*4,8:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        }
    }

    fn linux_2_4_x_v1() -> Self {
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
            sig: "*:64:0:*:mss*4,0:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        }
    }

    fn linux_2_4_x_v2() -> Self {
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
            sig: "*:64:0:*:mss*4,1:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        }
    }

    fn linux_2_4_x_v3() -> Self {
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
            sig: "*:64:0:*:mss*4,2:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        }
    }

    fn linux_2_2_x_v1() -> Self {
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
            sig: "*:64:0:*:mss*11,0:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        }
    }

    fn linux_2_2_x_v2() -> Self {
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
            sig: "*:64:0:*:mss*20,0:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        }
    }

    fn linux_2_2_x_v3() -> Self {
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
            sig: "*:64:0:*:mss*20,0:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        }
    }

    fn linux_2_0_v1() -> Self {
        Self {
            mss: 128,
            ittl: 64,
            window: 128 * 12,
            options: vec![TcpOption::mss(128)],
            sig: "*:64:0:*:mss*12,0:mss::0".to_string(),
        }
    }

    fn linux_2_0_v2() -> Self {
        Self {
            mss: 128,
            ittl: 64,
            window: 16384,
            options: vec![TcpOption::mss(128)],
            sig: "*:64:0:*:16384,0:mss::0".to_string(),
        }
    }

    fn linux_3_x_loopback_v1() -> Self {
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
            sig: "*:64:0:16396:mss*2,4:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        }
    }

    fn linux_3_x_loopback_v2() -> Self {
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
            sig: "*:64:0:16376:mss*2,4:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        }
    }

    fn linux_2_6_x_loopback_v1() -> Self {
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
            sig: "*:64:0:16396:mss*2,2:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        }
    }

    fn linux_2_6_x_loopback_v2() -> Self {
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
            sig: "*:64:0:16376:mss*2,2:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        }
    }

    fn linux_2_4_x_loopback() -> Self {
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
            sig: "*:64:0:16396:mss*2,0:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        }
    }

    fn linux_2_2_x_loopback() -> Self {
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
            sig: "*:64:0:3884:mss*8,0:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        }
    }

    fn solaris_8() -> Self {
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
            sig: "*:64:0:*:32850,1:nop,ws,nop,nop,ts,nop,nop,sok,mss:df,id+:0".to_string(),
        }
    }

    fn android() -> Self {
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
            sig: "*:64:0:*:mss*44,1:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        }
    }
}
