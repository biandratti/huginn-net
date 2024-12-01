use crate::{http, tcp};
use std::fmt;

/// Represents the database used by `P0f` to store signatures and associated metadata.
/// The database contains signatures for analyzing TCP and HTTP traffic, as well as
/// other metadata such as MTU mappings and user agent-to-operating system mappings.
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

/// Represents a label associated with a signature, which provides metadata about
/// the signature, such as type, class, name, and optional flavor details.
#[derive(Clone, Debug, PartialEq)]
pub struct Label {
    pub ty: Type,
    pub class: Option<String>,
    pub name: String,
    pub flavor: Option<String>,
}

/// Enum representing the type of `Label`.
/// - `Specified`: A specific label with well-defined characteristics.
/// - `Generic`: A generic label with broader characteristics.
#[derive(Clone, Debug, PartialEq)]
pub enum Type {
    Specified,
    Generic,
}

impl fmt::Display for Type {
    /// Creates a default instance of the `Database` by parsing a configuration file
    /// located at `config/p0f.fp`. This file is expected to define the default
    /// signatures and mappings used for analysis.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
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
