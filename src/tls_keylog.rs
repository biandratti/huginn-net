use crate::error::HuginnNetError;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tracing::{debug, warn};

/// Types of TLS key material found in keylog files
#[derive(Debug, Clone, PartialEq)]
pub enum KeyType {
    /// TLS 1.2 master secret
    ClientRandom,
    /// TLS 1.3 client traffic secret
    ClientTrafficSecret0,
    /// TLS 1.3 server traffic secret
    ServerTrafficSecret0,
    /// TLS 1.3 client handshake traffic secret
    ClientHandshakeTrafficSecret,
    /// TLS 1.3 server handshake traffic secret
    ServerHandshakeTrafficSecret,
    /// Unknown key type
    Unknown(String),
}

impl From<&str> for KeyType {
    fn from(s: &str) -> Self {
        match s {
            "CLIENT_RANDOM" => KeyType::ClientRandom,
            "CLIENT_TRAFFIC_SECRET_0" => KeyType::ClientTrafficSecret0,
            "SERVER_TRAFFIC_SECRET_0" => KeyType::ServerTrafficSecret0,
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => KeyType::ClientHandshakeTrafficSecret,
            "SERVER_HANDSHAKE_TRAFFIC_SECRET" => KeyType::ServerHandshakeTrafficSecret,
            other => KeyType::Unknown(other.to_string()),
        }
    }
}

/// TLS key material extracted from keylog files
#[derive(Debug, Clone)]
pub struct KeyMaterial {
    /// Type of key material
    pub key_type: KeyType,
    /// Client random (32 bytes)
    pub client_random: Vec<u8>,
    /// Key material (varies by type)
    pub key_data: Vec<u8>,
}

/// Parser for TLS keylog files (SSLKEYLOGFILE format)
///
/// Supports the standard format used by browsers and applications:
/// ```text
/// CLIENT_RANDOM <client_random> <master_secret>
/// CLIENT_TRAFFIC_SECRET_0 <client_random> <secret>
/// SERVER_TRAFFIC_SECRET_0 <client_random> <secret>
/// ```
#[derive(Debug, Clone)]
pub struct TlsKeylog {
    /// Map from client_random to key material
    keys: HashMap<Vec<u8>, Vec<KeyMaterial>>,
    /// Total number of keys loaded
    key_count: usize,
}

impl TlsKeylog {
    /// Create a new empty keylog
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            key_count: 0,
        }
    }

    /// Load keylog from file
    ///
    /// # Arguments
    /// * `path` - Path to the keylog file
    ///
    /// # Returns
    /// * `Ok(TlsKeylog)` - Successfully loaded keylog
    /// * `Err(HuginnNetError)` - Failed to load or parse keylog
    ///
    /// # Example
    /// ```rust
    /// use std::path::Path;
    /// use huginn_net::tls_keylog::TlsKeylog;
    ///
    /// let keylog = TlsKeylog::from_file(Path::new("/tmp/sslkeylog.txt"))?;
    /// ```
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, HuginnNetError> {
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| HuginnNetError::Parse(format!("Failed to read keylog file: {e}")))?;

        Self::from_string(&content)
    }

    /// Load keylog from string content
    ///
    /// # Arguments
    /// * `content` - Keylog file content
    ///
    /// # Returns
    /// * `Ok(TlsKeylog)` - Successfully parsed keylog
    /// * `Err(HuginnNetError)` - Failed to parse keylog
    pub fn from_string(content: &str) -> Result<Self, HuginnNetError> {
        let mut keylog = Self::new();

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            match keylog.parse_line(line) {
                Ok(Some(key_material)) => {
                    keylog.add_key_material(key_material);
                }
                Ok(None) => {
                    // Line was skipped (unknown format but not an error)
                    debug!(
                        "Skipped keylog line {}: {}",
                        line_num.saturating_add(1),
                        line
                    );
                }
                Err(e) => {
                    warn!(
                        "Error parsing keylog line {}: {} - {}",
                        line_num.saturating_add(1),
                        line,
                        e
                    );
                    // Continue parsing other lines instead of failing completely
                }
            }
        }

        debug!("Loaded {} key entries from keylog", keylog.key_count);
        Ok(keylog)
    }

    /// Parse a single keylog line
    ///
    /// # Arguments
    /// * `line` - Single line from keylog file
    ///
    /// # Returns
    /// * `Ok(Some(KeyMaterial))` - Successfully parsed key material
    /// * `Ok(None)` - Line was skipped (unknown format)
    /// * `Err(HuginnNetError)` - Parse error
    fn parse_line(&self, line: &str) -> Result<Option<KeyMaterial>, HuginnNetError> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() != 3 {
            return Ok(None); // Skip malformed lines
        }

        let key_type = KeyType::from(parts[0]);

        // Only process known key types
        if let KeyType::Unknown(_) = key_type {
            return Ok(None);
        }

        let client_random = hex::decode(parts[1])
            .map_err(|e| HuginnNetError::Parse(format!("Invalid client_random hex: {e}")))?;

        let key_data = hex::decode(parts[2])
            .map_err(|e| HuginnNetError::Parse(format!("Invalid key_data hex: {e}")))?;

        // Validate client_random length (should be 32 bytes)
        if client_random.len() != 32 {
            return Err(HuginnNetError::Parse(format!(
                "Invalid client_random length: expected 32, got {}",
                client_random.len()
            )));
        }

        Ok(Some(KeyMaterial {
            key_type,
            client_random,
            key_data,
        }))
    }

    /// Add key material to the keylog
    fn add_key_material(&mut self, key_material: KeyMaterial) {
        let client_random = key_material.client_random.clone();

        self.keys
            .entry(client_random)
            .or_default()
            .push(key_material);

        self.key_count = self.key_count.saturating_add(1);
    }

    /// Find key material by client random
    ///
    /// # Arguments
    /// * `client_random` - 32-byte client random from TLS handshake
    ///
    /// # Returns
    /// * `Some(&[KeyMaterial])` - Found key material for this client random
    /// * `None` - No key material found
    pub fn find_keys(&self, client_random: &[u8]) -> Option<&[KeyMaterial]> {
        self.keys.get(client_random).map(|v| v.as_slice())
    }

    /// Find specific key type by client random
    ///
    /// # Arguments
    /// * `client_random` - 32-byte client random from TLS handshake
    /// * `key_type` - Type of key to find
    ///
    /// # Returns
    /// * `Some(&KeyMaterial)` - Found key material of specified type
    /// * `None` - No key material of this type found
    pub fn find_key_by_type(
        &self,
        client_random: &[u8],
        key_type: &KeyType,
    ) -> Option<&KeyMaterial> {
        self.find_keys(client_random)?
            .iter()
            .find(|key| &key.key_type == key_type)
    }

    /// Get total number of keys loaded
    pub fn key_count(&self) -> usize {
        self.key_count
    }

    /// Get number of unique client randoms
    pub fn client_count(&self) -> usize {
        self.keys.len()
    }

    /// Check if keylog is empty
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl Default for TlsKeylog {
    fn default() -> Self {
        Self::new()
    }
}

/// Manager for multiple TLS keylog files
///
/// Handles multiple keylog files for different certificates/domains.
/// Searches across all loaded keylogs to find the appropriate key material.
#[derive(Debug, Clone)]
pub struct TlsKeylogManager {
    /// List of loaded keylogs with their source information
    keylogs: Vec<(String, TlsKeylog)>, // (source_name, keylog)
    /// Total number of keys across all keylogs
    total_keys: usize,
}

impl TlsKeylogManager {
    /// Create a new empty keylog manager
    pub fn new() -> Self {
        Self {
            keylogs: Vec::new(),
            total_keys: 0,
        }
    }

    /// Load keylogs from multiple files
    ///
    /// # Arguments
    /// * `paths` - Vector of paths to keylog files
    ///
    /// # Returns
    /// * `Ok(TlsKeylogManager)` - Successfully loaded manager
    /// * `Err(HuginnNetError)` - Failed to load one or more keylogs
    ///
    /// # Example
    /// ```rust
    /// use std::path::PathBuf;
    /// use huginn_net::tls_keylog::TlsKeylogManager;
    ///
    /// let paths = vec![
    ///     PathBuf::from("/tmp/example.com.keylog"),
    ///     PathBuf::from("/tmp/api.example.com.keylog"),
    ///     PathBuf::from("/tmp/cdn.example.com.keylog"),
    /// ];
    /// let manager = TlsKeylogManager::from_files(&paths)?;
    /// ```
    pub fn from_files<P: AsRef<std::path::Path>>(paths: &[P]) -> Result<Self, HuginnNetError> {
        let mut manager = Self::new();

        for path in paths {
            let path_ref = path.as_ref();
            let source_name = path_ref
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("unknown")
                .to_string();

            match TlsKeylog::from_file(path_ref) {
                Ok(keylog) => {
                    debug!(
                        "Loaded keylog from {}: {} keys",
                        source_name,
                        keylog.key_count()
                    );
                    manager.add_keylog(source_name, keylog);
                }
                Err(e) => {
                    warn!("Failed to load keylog from {}: {}", source_name, e);
                    // Continue loading other keylogs instead of failing completely
                }
            }
        }

        if manager.keylogs.is_empty() {
            return Err(HuginnNetError::Parse(
                "No keylog files could be loaded".to_string(),
            ));
        }

        debug!(
            "Loaded {} keylog files with {} total keys",
            manager.keylogs.len(),
            manager.total_keys
        );

        Ok(manager)
    }

    /// Add a keylog from string content with a source name
    ///
    /// # Arguments
    /// * `source_name` - Name/identifier for this keylog (e.g., domain name)
    /// * `content` - Keylog file content
    ///
    /// # Returns
    /// * `Ok(())` - Successfully added keylog
    /// * `Err(HuginnNetError)` - Failed to parse keylog
    pub fn add_keylog_from_string(
        &mut self,
        source_name: String,
        content: &str,
    ) -> Result<(), HuginnNetError> {
        let keylog = TlsKeylog::from_string(content)?;
        self.add_keylog(source_name, keylog);
        Ok(())
    }

    /// Add a pre-loaded keylog
    fn add_keylog(&mut self, source_name: String, keylog: TlsKeylog) {
        self.total_keys = self.total_keys.saturating_add(keylog.key_count());
        self.keylogs.push((source_name, keylog));
    }

    /// Find key material by client random across all keylogs
    ///
    /// # Arguments
    /// * `client_random` - 32-byte client random from TLS handshake
    ///
    /// # Returns
    /// * `Some((&str, &[KeyMaterial]))` - Found key material with source name
    /// * `None` - No key material found in any keylog
    pub fn find_keys(&self, client_random: &[u8]) -> Option<(&str, &[KeyMaterial])> {
        for (source_name, keylog) in &self.keylogs {
            if let Some(keys) = keylog.find_keys(client_random) {
                return Some((source_name, keys));
            }
        }
        None
    }

    /// Find specific key type by client random across all keylogs
    ///
    /// # Arguments
    /// * `client_random` - 32-byte client random from TLS handshake
    /// * `key_type` - Type of key to find
    ///
    /// # Returns
    /// * `Some((&str, &KeyMaterial))` - Found key material with source name
    /// * `None` - No key material of this type found in any keylog
    pub fn find_key_by_type(
        &self,
        client_random: &[u8],
        key_type: &KeyType,
    ) -> Option<(&str, &KeyMaterial)> {
        for (source_name, keylog) in &self.keylogs {
            if let Some(key) = keylog.find_key_by_type(client_random, key_type) {
                return Some((source_name, key));
            }
        }
        None
    }

    /// Get total number of keys across all keylogs
    pub fn total_key_count(&self) -> usize {
        self.total_keys
    }

    /// Get number of loaded keylog files
    pub fn keylog_count(&self) -> usize {
        self.keylogs.len()
    }

    /// Get total number of unique client randoms across all keylogs
    pub fn total_client_count(&self) -> usize {
        self.keylogs
            .iter()
            .map(|(_, keylog)| keylog.client_count())
            .sum()
    }

    /// Check if manager has any keylogs loaded
    pub fn is_empty(&self) -> bool {
        self.keylogs.is_empty()
    }

    /// Get information about loaded keylogs
    pub fn keylog_info(&self) -> Vec<(String, usize, usize)> {
        self.keylogs
            .iter()
            .map(|(name, keylog)| (name.clone(), keylog.key_count(), keylog.client_count()))
            .collect()
    }

    /// Find all keylogs that contain keys for a specific client random
    ///
    /// This is useful for debugging when multiple keylogs might have keys for the same session
    pub fn find_all_matching_keylogs(&self, client_random: &[u8]) -> Vec<(&str, &[KeyMaterial])> {
        self.keylogs
            .iter()
            .filter_map(|(source_name, keylog)| {
                keylog
                    .find_keys(client_random)
                    .map(|keys| (source_name.as_str(), keys))
            })
            .collect()
    }
}

impl Default for TlsKeylogManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_client_random_line() {
        let keylog = TlsKeylog::new();
        let line = "CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

        match keylog.parse_line(line) {
            Ok(Some(result)) => {
                assert_eq!(result.key_type, KeyType::ClientRandom);
                assert_eq!(result.client_random.len(), 32);
                assert_eq!(result.key_data.len(), 32);
            }
            _ => panic!("Should parse line and have key material"),
        }
    }

    #[test]
    fn test_parse_tls13_line() {
        let keylog = TlsKeylog::new();
        let line = "CLIENT_TRAFFIC_SECRET_0 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

        match keylog.parse_line(line) {
            Ok(Some(result)) => {
                assert_eq!(result.key_type, KeyType::ClientTrafficSecret0);
            }
            _ => panic!("Should parse line and have key material"),
        }
    }

    #[test]
    fn test_skip_unknown_line() {
        let keylog = TlsKeylog::new();
        let line = "UNKNOWN_KEY_TYPE 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

        match keylog.parse_line(line) {
            Ok(None) => {
                // Expected: unknown key types should be skipped
            }
            _ => panic!("Should parse line but return None for unknown key type"),
        }
    }

    #[test]
    fn test_skip_comment_and_empty_lines() {
        let content = r#"
# This is a comment
CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210

# Another comment
CLIENT_TRAFFIC_SECRET_0 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
"#;

        match TlsKeylog::from_string(content) {
            Ok(keylog) => {
                assert_eq!(keylog.key_count(), 2);
                assert_eq!(keylog.client_count(), 1);
            }
            Err(_) => panic!("Should parse keylog content"),
        }
    }

    #[test]
    fn test_find_keys() {
        let content = r#"
CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
CLIENT_TRAFFIC_SECRET_0 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
"#;

        let keylog = match TlsKeylog::from_string(content) {
            Ok(keylog) => keylog,
            Err(_) => panic!("Should parse keylog"),
        };

        let client_random =
            match hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") {
                Ok(bytes) => bytes,
                Err(_) => panic!("Should decode hex"),
            };

        let keys = match keylog.find_keys(&client_random) {
            Some(keys) => keys,
            None => panic!("Should find keys"),
        };
        assert_eq!(keys.len(), 2);

        let master_secret = keylog.find_key_by_type(&client_random, &KeyType::ClientRandom);
        assert!(master_secret.is_some());

        let traffic_secret =
            keylog.find_key_by_type(&client_random, &KeyType::ClientTrafficSecret0);
        assert!(traffic_secret.is_some());
    }

    #[test]
    fn test_keylog_manager_multiple_files() {
        let content1 = r#"
CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
"#;
        let content2 = r#"
CLIENT_RANDOM abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba
CLIENT_TRAFFIC_SECRET_0 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876
"#;

        let mut manager = TlsKeylogManager::new();

        if manager
            .add_keylog_from_string("example.com".to_string(), content1)
            .is_err()
        {
            panic!("Should add keylog");
        }
        if manager
            .add_keylog_from_string("api.example.com".to_string(), content2)
            .is_err()
        {
            panic!("Should add keylog");
        }

        assert_eq!(manager.keylog_count(), 2);
        assert_eq!(manager.total_key_count(), 3);
        assert_eq!(manager.total_client_count(), 2);

        // Test finding keys from first keylog
        let client_random1 =
            match hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") {
                Ok(bytes) => bytes,
                Err(_) => panic!("Should decode hex"),
            };
        let (source, keys) = match manager.find_keys(&client_random1) {
            Some(result) => result,
            None => panic!("Should find keys"),
        };
        assert_eq!(source, "example.com");
        assert_eq!(keys.len(), 1);

        // Test finding keys from second keylog
        let client_random2 =
            match hex::decode("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789") {
                Ok(bytes) => bytes,
                Err(_) => panic!("Should decode hex"),
            };
        let (source, keys) = match manager.find_keys(&client_random2) {
            Some(result) => result,
            None => panic!("Should find keys"),
        };
        assert_eq!(source, "api.example.com");
        assert_eq!(keys.len(), 2);

        // Test finding specific key type
        let (source, _key) =
            match manager.find_key_by_type(&client_random2, &KeyType::ClientTrafficSecret0) {
                Some(result) => result,
                None => panic!("Should find key"),
            };
        assert_eq!(source, "api.example.com");
    }

    #[test]
    fn test_keylog_manager_info() {
        let content = r#"
CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
CLIENT_TRAFFIC_SECRET_0 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
"#;

        let mut manager = TlsKeylogManager::new();
        if manager
            .add_keylog_from_string("test.com".to_string(), content)
            .is_err()
        {
            panic!("Should add keylog");
        }

        let info = manager.keylog_info();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].0, "test.com");
        assert_eq!(info[0].1, 2); // key count
        assert_eq!(info[0].2, 1); // client count
    }
}
