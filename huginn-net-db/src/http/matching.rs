//! Glue between [`huginn_net_http::observable`] and the database matcher.

use crate::database::HttpIndexKey;
use crate::db_matching_trait::{DatabaseSignature, NoFuzziness, ObservedFingerprint, SignatureFit};
use huginn_net_http::observable::{HttpRequestObservation, HttpResponseObservation};

use super::{
    absent_headers_match, headers_match, http_version_matches, Header, Signature, Version,
};

impl ObservedFingerprint for HttpRequestObservation {
    type Key = HttpIndexKey;

    fn generate_index_key(&self) -> Self::Key {
        HttpIndexKey { http_version_key: self.version }
    }
}

impl ObservedFingerprint for HttpResponseObservation {
    type Key = HttpIndexKey;

    fn generate_index_key(&self) -> Self::Key {
        HttpIndexKey { http_version_key: self.version }
    }
}

impl Signature {
    /// Version / `horder` / `habsent` only. `expsw` is checked after the match.
    fn http_fit(&self, version: Version, horder: &[Header]) -> Option<SignatureFit<NoFuzziness>> {
        let gates = http_version_matches(version, self.version)
            && headers_match(horder, &self.horder)
            && absent_headers_match(horder, &self.habsent);

        gates.then(SignatureFit::exact)
    }

    fn generate_http_index_keys(&self) -> Vec<HttpIndexKey> {
        let mut keys = Vec::new();
        if self.version == Version::Any {
            keys.push(HttpIndexKey { http_version_key: Version::V10 });
            keys.push(HttpIndexKey { http_version_key: Version::V11 });
        } else {
            keys.push(HttpIndexKey { http_version_key: self.version });
        }
        keys
    }
}

impl DatabaseSignature<HttpRequestObservation> for Signature {
    type Fuzziness = NoFuzziness;

    fn fit(&self, observed: &HttpRequestObservation) -> Option<SignatureFit<NoFuzziness>> {
        self.http_fit(observed.version, &observed.horder)
    }
    fn generate_index_keys_for_db_entry(&self) -> Vec<HttpIndexKey> {
        self.generate_http_index_keys()
    }
}

impl DatabaseSignature<HttpResponseObservation> for Signature {
    type Fuzziness = NoFuzziness;

    fn fit(&self, observed: &HttpResponseObservation) -> Option<SignatureFit<NoFuzziness>> {
        self.http_fit(observed.version, &observed.horder)
    }
    fn generate_index_keys_for_db_entry(&self) -> Vec<HttpIndexKey> {
        self.generate_http_index_keys()
    }
}
