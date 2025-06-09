use crate::db::TcpP0fIndexKey;
use crate::db_matching_trait::{DatabaseSignature, MatchQuality, ObservedFingerprint};
use crate::observable_signals::ObservableTcp;
use crate::tcp;
use crate::tcp::{IpVersion, PayloadSize, TcpMatchQuality};

impl ObservableTcp {
    fn distance_olen(&self, other: &tcp::Signature) -> Option<u32> {
        if self.olen == other.olen {
            Some(TcpMatchQuality::High.as_score())
        } else {
            Some(TcpMatchQuality::Low.as_score())
        }
    }

    fn distance_mss(&self, other: &tcp::Signature) -> Option<u32> {
        if other.mss.is_none() || self.mss == other.mss {
            Some(TcpMatchQuality::High.as_score())
        } else {
            Some(TcpMatchQuality::Low.as_score())
        }
    }

    fn distance_wscale(&self, other: &tcp::Signature) -> Option<u32> {
        if other.wscale.is_none() || self.wscale == other.wscale {
            Some(TcpMatchQuality::High.as_score())
        } else {
            Some(TcpMatchQuality::Medium.as_score())
        }
    }

    fn distance_olayout(&self, other: &tcp::Signature) -> Option<u32> {
        if self.olayout == other.olayout {
            Some(TcpMatchQuality::High.as_score())
        } else {
            None
        }
    }

    fn distance_quirks(&self, other: &tcp::Signature) -> Option<u32> {
        if self.quirks == other.quirks {
            Some(TcpMatchQuality::High.as_score())
        } else {
            None
        }
    }
}

impl ObservedFingerprint for ObservableTcp {
    type Key = TcpP0fIndexKey;

    fn generate_index_key(&self) -> Self::Key {
        let olayout_parts: Vec<String> =
            self.olayout.iter().map(|opt| format!("{}", opt)).collect();
        TcpP0fIndexKey {
            ip_version_key: self.version,
            olayout_key: olayout_parts.join(","),
            pclass_key: self.pclass,
        }
    }
}

impl DatabaseSignature<ObservableTcp> for tcp::Signature {
    fn calculate_distance(&self, observed: &ObservableTcp) -> Option<u32> {
        let distance = observed.version.distance_ip_version(&self.version)?
            + observed.ittl.distance_ttl(&self.ittl)?
            + observed.distance_olen(self)?
            + observed.distance_mss(self)?
            + observed
                .wsize
                .distance_window_size(&self.wsize, observed.mss)?
            + observed.distance_wscale(self)?
            + observed.distance_olayout(self)?
            + observed.distance_quirks(self)?
            + observed.pclass.distance_payload_size(&self.pclass)?;
        Some(distance)
    }

    /// Returns the quality score based on the distance.
    ///
    /// The score is a value between 0.0 and 1.0, where 1.0 is a perfect match.
    ///
    /// The score is calculated based on the distance of the observed signal to the database signature.
    /// The distance is a value between 0 and 18, where 0 is a perfect match and 18 is the maximum possible distance.
    ///
    fn get_quality_score(&self, distance: u32) -> MatchQuality {
        // For TCP with 9 hypothetical components:
        // - Each component: 0 (High), 1 (Medium), 2 (Low), 3 (Bad)
        // - Maximum theoretical distance: 18 (all Bad)
        match distance {
            0 => 1.0,
            1 => 0.95,
            2 => 0.90,
            3..=4 => 0.80,
            5..=6 => 0.70,
            7..=9 => 0.60,
            10..=12 => 0.40,
            13..=15 => 0.20,
            16..=18 => 0.10,
            _ => 0.05,
        }
    }

    fn generate_index_keys_for_db_entry(&self) -> Vec<TcpP0fIndexKey> {
        let mut keys = Vec::new();
        let olayout_key_str = self
            .olayout
            .iter()
            .map(|opt| format!("{}", opt))
            .collect::<Vec<String>>()
            .join(",");

        let versions_for_keys = if self.version == IpVersion::Any {
            vec![IpVersion::V4, IpVersion::V6]
        } else {
            vec![self.version]
        };

        let pclasses_for_keys = if self.pclass == PayloadSize::Any {
            vec![PayloadSize::Zero, PayloadSize::NonZero]
        } else {
            vec![self.pclass]
        };

        for v_key_part in &versions_for_keys {
            for pc_key_part in &pclasses_for_keys {
                keys.push(TcpP0fIndexKey {
                    ip_version_key: *v_key_part,
                    olayout_key: olayout_key_str.clone(),
                    pclass_key: *pc_key_part,
                });
            }
        }
        keys
    }
}
