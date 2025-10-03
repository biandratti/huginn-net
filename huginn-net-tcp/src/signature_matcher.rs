use crate::db::{db_matching_trait::FingerprintDb, Database, Label};
use crate::observable::ObservableTcp;

pub struct SignatureMatcher<'a> {
    database: &'a Database,
}

impl<'a> SignatureMatcher<'a> {
    pub fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn matching_by_tcp_request(
        &self,
        signature: &ObservableTcp,
    ) -> Option<(&'a Label, &'a crate::tcp::Signature, f32)> {
        self.database
            .tcp_request
            .find_best_match(&signature.matching)
    }

    pub fn matching_by_tcp_response(
        &self,
        signature: &ObservableTcp,
    ) -> Option<(&'a Label, &'a crate::tcp::Signature, f32)> {
        self.database
            .tcp_response
            .find_best_match(&signature.matching)
    }

    pub fn matching_by_mtu(&self, mtu: &u16) -> Option<(&'a String, &'a u16)> {
        for (link, db_mtus) in &self.database.mtu {
            for db_mtu in db_mtus {
                if mtu == db_mtu {
                    return Some((link, db_mtu));
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::{IpVersion, PayloadSize, Quirk, TcpOption, Ttl, WindowSize};
    use huginn_net_db::observable_signals::TcpObservation;
    use huginn_net_db::Type;

    #[test]
    fn matching_linux_by_tcp_request() {
        let db = match Database::load_default() {
            Ok(db) => db,
            Err(e) => {
                panic!("Failed to create default database: {e}");
            }
        };

        //sig: 4:58+6:0:1452:mss*44,7:mss,sok,ts,nop,ws:df,id+:0
        let linux_signature = ObservableTcp {
            matching: TcpObservation {
                version: IpVersion::V4,
                ittl: Ttl::Distance(58, 6),
                olen: 0,
                mss: Some(1452),
                wsize: WindowSize::Mss(44),
                wscale: Some(7),
                olayout: vec![
                    TcpOption::Mss,
                    TcpOption::Sok,
                    TcpOption::TS,
                    TcpOption::Nop,
                    TcpOption::Ws,
                ],
                quirks: vec![Quirk::Df, Quirk::NonZeroID],
                pclass: PayloadSize::Zero,
            },
        };

        let matcher = SignatureMatcher::new(&db);

        if let Some((label, _matched_db_sig, quality)) =
            matcher.matching_by_tcp_request(&linux_signature)
        {
            assert_eq!(label.name, "Linux");
            assert_eq!(label.class, Some("unix".to_string()));
            assert_eq!(label.flavor, Some("2.2.x-3.x".to_string()));
            assert_eq!(label.ty, Type::Generic);
            assert_eq!(quality, 1.0);
        } else {
            panic!("No match found");
        }
    }

    #[test]
    fn matching_android_by_tcp_request() {
        let db = match Database::load_default() {
            Ok(db) => db,
            Err(e) => {
                panic!("Failed to create default database: {e}");
            }
        };

        //sig: "4:64+0:0:1460:65535,8:mss,sok,ts,nop,ws:df,id+:0"
        let android_signature = ObservableTcp {
            matching: TcpObservation {
                version: IpVersion::V4,
                ittl: Ttl::Value(64),
                olen: 0,
                mss: Some(1460),
                wsize: WindowSize::Value(65535),
                wscale: Some(8),
                olayout: vec![
                    TcpOption::Mss,
                    TcpOption::Sok,
                    TcpOption::TS,
                    TcpOption::Nop,
                    TcpOption::Ws,
                ],
                quirks: vec![Quirk::Df, Quirk::NonZeroID],
                pclass: PayloadSize::Zero,
            },
        };

        //sig: "4:57+7:0:1460:65535,8:mss,sok,ts,nop,ws:df,id+:0"
        let android_signature_with_distance = ObservableTcp {
            matching: TcpObservation {
                version: IpVersion::V4,
                ittl: Ttl::Distance(57, 7),
                olen: 0,
                mss: Some(1460),
                wsize: WindowSize::Value(65535),
                wscale: Some(8),
                olayout: vec![
                    TcpOption::Mss,
                    TcpOption::Sok,
                    TcpOption::TS,
                    TcpOption::Nop,
                    TcpOption::Ws,
                ],
                quirks: vec![Quirk::Df, Quirk::NonZeroID],
                pclass: PayloadSize::Zero,
            },
        };

        let matcher = SignatureMatcher::new(&db);

        if let Some((label, _matched_db_sig, quality)) =
            matcher.matching_by_tcp_request(&android_signature)
        {
            assert_eq!(label.name, "Linux");
            assert_eq!(label.class, Some("unix".to_string()));
            assert_eq!(label.flavor, Some("Android".to_string()));
            assert_eq!(label.ty, Type::Specified);
            assert_eq!(quality, 1.0);
        } else {
            panic!("No match found");
        }

        if let Some((label, _matched_db_sig, quality)) =
            matcher.matching_by_tcp_request(&android_signature_with_distance)
        {
            assert_eq!(label.name, "Linux");
            assert_eq!(label.class, Some("unix".to_string()));
            assert_eq!(label.flavor, Some("Android".to_string()));
            assert_eq!(label.ty, Type::Specified);
            assert_eq!(quality, 1.0);
        } else {
            panic!("No match found");
        }
    }
}
