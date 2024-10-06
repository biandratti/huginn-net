use crate::{http, tcp, Label};

#[allow(dead_code)] //TODO: WIP
#[derive(Debug)]
pub struct Database {
    pub classes: Vec<String>,
    pub mtu: Vec<(String, Vec<u16>)>,
    pub ua_os: Vec<(String, Option<String>)>,
    pub tcp_request: Vec<(Label, Vec<tcp::Signature>)>,
    pub tcp_response: Vec<(Label, Vec<tcp::Signature>)>,
    pub http_request: Vec<(Label, Vec<http::Signature>)>,
    pub http_response: Vec<(Label, Vec<http::Signature>)>,
}

impl Default for Database {
    fn default() -> Self {
        include_str!("../config/p0f.fp")
            .parse()
            .expect("parse default database")
    }
}

#[cfg(test)]
mod tests {

    #[cfg(feature = "parse")]
    #[test]
    fn test_default_database() {
        let _ = pretty_env_logger::try_init();

        let db = Database::default();

        assert_eq!(db.classes, vec!["win", "unix", "other"]);

        assert_eq!(
            db.mtu,
            vec![
                ("Ethernet or modem".to_owned(), vec![576, 1500]),
                ("DSL".to_owned(), vec![1452, 1454, 1492]),
                ("GIF".to_owned(), vec![1240, 1280]),
                (
                    "generic tunnel or VPN".to_owned(),
                    vec![1300, 1400, 1420, 1440, 1450, 1460]
                ),
                ("IPSec or GRE".to_owned(), vec![1476]),
                ("IPIP or SIT".to_owned(), vec![1480]),
                ("PPTP".to_owned(), vec![1490]),
                ("AX.25 radio modem".to_owned(), vec![256]),
                ("SLIP".to_owned(), vec![552]),
                ("Google".to_owned(), vec![1470]),
                ("VLAN".to_owned(), vec![1496]),
                ("Ericsson HIS modem".to_owned(), vec![1656]),
                ("jumbo Ethernet".to_owned(), vec![9000]),
                ("loopback".to_owned(), vec![3924, 16384, 16436])
            ]
        );
    }
}
