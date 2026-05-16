use crate::database::TcpIndexKey;
use crate::db_matching_trait::{DatabaseSignature, MatchQuality, ObservedFingerprint};
use crate::observable_signals::TcpObservation;
use crate::tcp::{
    self, distance_ip_version, distance_payload_size, distance_ttl, distance_window_size,
    IpVersion, PayloadSize,
};

pub(crate) fn distance_olen(observed: &TcpObservation, signature: &tcp::Signature) -> Option<u32> {
    if observed.olen == signature.olen {
        Some(tcp::TcpMatchQuality::High.as_score())
    } else {
        Some(tcp::TcpMatchQuality::Low.as_score())
    }
}

pub(crate) fn distance_mss(observed: &TcpObservation, signature: &tcp::Signature) -> Option<u32> {
    if signature.mss.is_none() || observed.mss == signature.mss {
        Some(tcp::TcpMatchQuality::High.as_score())
    } else {
        Some(tcp::TcpMatchQuality::Low.as_score())
    }
}

pub(crate) fn distance_wscale(
    observed: &TcpObservation,
    signature: &tcp::Signature,
) -> Option<u32> {
    if signature.wscale.is_none() || observed.wscale == signature.wscale {
        Some(tcp::TcpMatchQuality::High.as_score())
    } else {
        Some(tcp::TcpMatchQuality::Medium.as_score())
    }
}

pub(crate) fn distance_olayout(
    observed: &TcpObservation,
    signature: &tcp::Signature,
) -> Option<u32> {
    if observed.olayout == signature.olayout {
        Some(tcp::TcpMatchQuality::High.as_score())
    } else {
        None
    }
}

pub(crate) fn distance_quirks(
    observed: &TcpObservation,
    signature: &tcp::Signature,
) -> Option<u32> {
    if observed.quirks == signature.quirks {
        Some(tcp::TcpMatchQuality::High.as_score())
    } else {
        None
    }
}

impl ObservedFingerprint for TcpObservation {
    type Key = TcpIndexKey;

    fn generate_index_key(&self) -> Self::Key {
        let olayout_parts: Vec<String> = self.olayout.iter().map(|opt| format!("{opt}")).collect();
        TcpIndexKey {
            ip_version_key: self.version,
            olayout_key: olayout_parts.join(","),
            pclass_key: self.pclass,
        }
    }
}

impl DatabaseSignature<TcpObservation> for tcp::Signature {
    fn calculate_distance(&self, observed: &TcpObservation) -> Option<u32> {
        let distance = distance_ip_version(&observed.version, &self.version)?
            .saturating_add(distance_ttl(&observed.ittl, &self.ittl)?)
            .saturating_add(distance_olen(observed, self)?)
            .saturating_add(distance_mss(observed, self)?)
            .saturating_add(distance_window_size(&observed.wsize, &self.wsize, observed.mss)?)
            .saturating_add(distance_wscale(observed, self)?)
            .saturating_add(distance_olayout(observed, self)?)
            .saturating_add(distance_quirks(observed, self)?)
            .saturating_add(distance_payload_size(&observed.pclass, &self.pclass)?);
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
        tcp::TcpMatchQuality::distance_to_score(distance)
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
