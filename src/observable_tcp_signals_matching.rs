use crate::observable_signals::ObservableTcp;
use huginn_net_db::db::TcpIndexKey;
use huginn_net_db::db_matching_trait::{DatabaseSignature, MatchQuality, ObservedFingerprint};
use huginn_net_db::tcp;
use huginn_net_db::tcp::{IpVersion, PayloadSize, TcpMatchQuality};

impl ObservableTcp {
    fn distance_olen(&self, other: &tcp::Signature) -> Option<u32> {
        if self.matching.olen == other.olen {
            Some(TcpMatchQuality::High.as_score())
        } else {
            Some(TcpMatchQuality::Low.as_score())
        }
    }

    fn distance_mss(&self, other: &tcp::Signature) -> Option<u32> {
        if other.mss.is_none() || self.matching.mss == other.mss {
            Some(TcpMatchQuality::High.as_score())
        } else {
            Some(TcpMatchQuality::Low.as_score())
        }
    }

    fn distance_wscale(&self, other: &tcp::Signature) -> Option<u32> {
        if other.wscale.is_none() || self.matching.wscale == other.wscale {
            Some(TcpMatchQuality::High.as_score())
        } else {
            Some(TcpMatchQuality::Medium.as_score())
        }
    }

    fn distance_olayout(&self, other: &tcp::Signature) -> Option<u32> {
        if self.matching.olayout == other.olayout {
            Some(TcpMatchQuality::High.as_score())
        } else {
            None
        }
    }

    fn distance_quirks(&self, other: &tcp::Signature) -> Option<u32> {
        if self.matching.quirks == other.quirks {
            Some(TcpMatchQuality::High.as_score())
        } else {
            None
        }
    }
}

impl ObservedFingerprint for ObservableTcp {
    type Key = TcpIndexKey;

    fn generate_index_key(&self) -> Self::Key {
        let olayout_parts: Vec<String> = self
            .matching
            .olayout
            .iter()
            .map(|opt| format!("{opt}"))
            .collect();
        TcpIndexKey {
            ip_version_key: self.matching.version,
            olayout_key: olayout_parts.join(","),
            pclass_key: self.matching.pclass,
        }
    }
}

impl DatabaseSignature<ObservableTcp> for tcp::Signature {
    fn calculate_distance(&self, observed: &ObservableTcp) -> Option<u32> {
        let distance = observed
            .matching
            .version
            .distance_ip_version(&self.version)?
            .saturating_add(observed.matching.ittl.distance_ttl(&self.ittl)?)
            .saturating_add(observed.distance_olen(self)?)
            .saturating_add(observed.distance_mss(self)?)
            .saturating_add(
                observed
                    .matching
                    .wsize
                    .distance_window_size(&self.wsize, observed.matching.mss)?,
            )
            .saturating_add(observed.distance_wscale(self)?)
            .saturating_add(observed.distance_olayout(self)?)
            .saturating_add(observed.distance_quirks(self)?)
            .saturating_add(
                observed
                    .matching
                    .pclass
                    .distance_payload_size(&self.pclass)?,
            );
        Some(distance)
    }

    /// Returns the quality score based on the distance.
    ///
    /// The score is a value between 0.0 and 1.0, where 1.0 is a perfect match.
    ///
    /// The score is calculated based on the distance of the observed signal to the database signature.
    /// The distance is a value between 0 and 18, where 0 is a perfect match and 18 is the maximum possible distance.
    ///
    fn get_quality_score(&self, distance: u32) -> f32 {
        TcpMatchQuality::distance_to_score(distance)
    }

    fn generate_index_keys_for_db_entry(&self) -> Vec<TcpIndexKey> {
        let mut keys = Vec::new();
        let olayout_key_str = self
            .olayout
            .iter()
            .map(|opt| format!("{opt}"))
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
                keys.push(TcpIndexKey {
                    ip_version_key: *v_key_part,
                    olayout_key: olayout_key_str.clone(),
                    pclass_key: *pc_key_part,
                });
            }
        }
        keys
    }
}
