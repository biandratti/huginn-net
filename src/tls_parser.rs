use crate::tls::{TlsSignature, TlsVersion};
use crate::error::PassiveTcpError;
use tracing::debug;

/// TLS Content Types
const TLS_HANDSHAKE: u8 = 0x16;

/// TLS Handshake Types  
const TLS_CLIENT_HELLO: u8 = 0x01;

/// Common TLS Extensions
pub mod extensions {
    pub const SERVER_NAME: u16 = 0x0000;
    pub const SUPPORTED_GROUPS: u16 = 0x000a;
    pub const EC_POINT_FORMATS: u16 = 0x000b;
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    pub const ALPN: u16 = 0x0010;
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
}

/// Parse TLS packet and extract ClientHello information
pub fn parse_tls_client_hello(data: &[u8]) -> Result<TlsSignature, PassiveTcpError> {
    if data.len() < 5 {
        return Err(PassiveTcpError::Parse("TLS packet too short".to_string()));
    }

    // Check if this is a TLS handshake record
    if data[0] != TLS_HANDSHAKE {
        return Err(PassiveTcpError::Parse("Not a TLS handshake".to_string()));
    }

    // Extract TLS version from record header
    let record_version = u16::from_be_bytes([data[1], data[2]]);
    debug!("TLS record version: 0x{:04x}", record_version);
    
    // Extract record length
    let record_length = u16::from_be_bytes([data[3], data[4]]) as usize;
    
    if data.len() < 5 + record_length {
        return Err(PassiveTcpError::Parse("Incomplete TLS record".to_string()));
    }

    let handshake_data = &data[5..5 + record_length];
    
    if handshake_data.is_empty() || handshake_data[0] != TLS_CLIENT_HELLO {
        return Err(PassiveTcpError::Parse("Not a ClientHello".to_string()));
    }

    parse_client_hello(handshake_data, record_version)
}

fn parse_client_hello(data: &[u8], _record_version: u16) -> Result<TlsSignature, PassiveTcpError> {
    if data.len() < 38 {
        return Err(PassiveTcpError::Parse("ClientHello too short".to_string()));
    }

    let mut offset = 0;
    
    // Skip handshake type (1 byte)
    offset += 1;
    
    // Skip handshake length (3 bytes)
    offset += 3;
    
    // Extract ClientHello version (legacy version for TLS 1.3 compatibility)
    let client_version = u16::from_be_bytes([data[offset], data[offset + 1]]);
    let mut version = TlsVersion::from(client_version);
    debug!("ClientHello legacy version: 0x{:04x} -> {:?}", client_version, version);
    offset += 2;
    
    // Skip random (32 bytes)
    offset += 32;
    
    // Parse session ID
    if offset >= data.len() {
        return Err(PassiveTcpError::Parse("Unexpected end of ClientHello".to_string()));
    }
    let session_id_length = data[offset] as usize;
    offset += 1 + session_id_length;
    
    // Parse cipher suites
    if offset + 2 > data.len() {
        return Err(PassiveTcpError::Parse("Cannot read cipher suites length".to_string()));
    }
    let cipher_suites_length = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;
    
    if offset + cipher_suites_length > data.len() {
        return Err(PassiveTcpError::Parse("Incomplete cipher suites".to_string()));
    }
    
    let mut cipher_suites = Vec::new();
    for i in (0..cipher_suites_length).step_by(2) {
        if offset + i + 1 < data.len() {
            let cipher = u16::from_be_bytes([data[offset + i], data[offset + i + 1]]);
            cipher_suites.push(cipher);
        }
    }
    offset += cipher_suites_length;
    
    // Parse compression methods
    if offset >= data.len() {
        return Err(PassiveTcpError::Parse("Cannot read compression methods".to_string()));
    }
    let compression_methods_length = data[offset] as usize;
    offset += 1 + compression_methods_length;
    
    // Parse extensions
    let mut extensions = Vec::new();
    let mut elliptic_curves = Vec::new();
    let mut elliptic_curve_point_formats = Vec::new();
    let mut signature_algorithms = Vec::new();
    let mut sni = None;
    
    if offset + 2 <= data.len() {
        let extensions_length = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        
        let extensions_end = offset + extensions_length;
        
        while offset + 4 <= extensions_end && offset + 4 <= data.len() {
            let extension_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let extension_length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;
            
            if offset + extension_length > data.len() {
                break;
            }
            
            extensions.push(extension_type);
            
            let extension_data = &data[offset..offset + extension_length];
            
            match extension_type {
                extensions::SERVER_NAME => {
                    sni = parse_sni_extension(extension_data);
                }
                extensions::SUPPORTED_GROUPS => {
                    elliptic_curves = parse_supported_groups(extension_data);
                }
                extensions::EC_POINT_FORMATS => {
                    elliptic_curve_point_formats = parse_ec_point_formats(extension_data);
                }
                extensions::SIGNATURE_ALGORITHMS => {
                    signature_algorithms = parse_signature_algorithms(extension_data);
                }
                extensions::SUPPORTED_VERSIONS => {
                    debug!("Found supported_versions extension");
                    // Parse supported_versions extension to get real TLS version
                    if let Some(real_version) = parse_supported_versions(extension_data) {
                        debug!("Updated version from {:?} to {:?}", version, real_version);
                        version = real_version;
                    }
                }
                _ => {} // Ignore other extensions for now
            }
            
            offset += extension_length;
        }
    }
    
    debug!("Final TLS version: {:?}", version);
    
    Ok(TlsSignature {
        version,
        cipher_suites,
        extensions,
        elliptic_curves,
        elliptic_curve_point_formats,
        signature_algorithms,
        sni,
    })
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }
    
    let list_length = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_length {
        return None;
    }
    
    let mut offset = 2;
    if offset < data.len() && data[offset] == 0x00 { // hostname type
        offset += 1;
        if offset + 2 <= data.len() {
            let hostname_length = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            if offset + hostname_length <= data.len() {
                return String::from_utf8(data[offset..offset + hostname_length].to_vec()).ok();
            }
        }
    }
    
    None
}

fn parse_supported_groups(data: &[u8]) -> Vec<u16> {
    if data.len() < 2 {
        return Vec::new();
    }
    
    let list_length = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_length {
        return Vec::new();
    }
    
    let mut groups = Vec::new();
    for i in (2..2 + list_length).step_by(2) {
        if i + 1 < data.len() {
            let group = u16::from_be_bytes([data[i], data[i + 1]]);
            groups.push(group);
        }
    }
    
    groups
}

fn parse_ec_point_formats(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    
    let list_length = data[0] as usize;
    if data.len() < 1 + list_length {
        return Vec::new();
    }
    
    data[1..1 + list_length].to_vec()
}

fn parse_signature_algorithms(data: &[u8]) -> Vec<u16> {
    if data.len() < 2 {
        return Vec::new();
    }
    
    let list_length = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_length {
        return Vec::new();
    }
    
    let mut algorithms = Vec::new();
    for i in (2..2 + list_length).step_by(2) {
        if i + 1 < data.len() {
            let algorithm = u16::from_be_bytes([data[i], data[i + 1]]);
            algorithms.push(algorithm);
        }
    }
    
    algorithms
}

fn parse_supported_versions(data: &[u8]) -> Option<TlsVersion> {
    if data.len() < 2 {
        debug!("supported_versions too short: {} bytes", data.len());
        return None;
    }
    
    let list_length = data[0] as usize;
    if data.len() < 1 + list_length {
        debug!("supported_versions incomplete: need {} bytes, have {}", 1 + list_length, data.len());
        return None;
    }
    
    debug!("Parsing supported_versions: {} bytes of versions", list_length);
    
    // Parse supported versions list (each version is 2 bytes)
    for i in (1..1 + list_length).step_by(2) {
        if i + 1 < data.len() {
            let version_bytes = u16::from_be_bytes([data[i], data[i + 1]]);
            let version = TlsVersion::from(version_bytes);
            debug!("Found supported version: 0x{:04x} -> {:?}", version_bytes, version);
            
            // Return the highest supported version (TLS 1.3 takes precedence)
            match version {
                TlsVersion::V1_3 => {
                    debug!("Selecting TLS 1.3");
                    return Some(version);
                }
                _ => continue,
            }
        }
    }
    
    // If no TLS 1.3 found, return the first supported version
    if list_length >= 2 {
        let version_bytes = u16::from_be_bytes([data[1], data[2]]);
        let version = TlsVersion::from(version_bytes);
        debug!("No TLS 1.3 found, using first version: 0x{:04x} -> {:?}", version_bytes, version);
        Some(version)
    } else {
        debug!("No valid versions found in supported_versions");
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tls_version() {
        assert_eq!(TlsVersion::from(0x0303), TlsVersion::V1_2);
        assert_eq!(TlsVersion::from(0x0304), TlsVersion::V1_3);
    }

    #[test]
    fn test_sni_parsing() {
        // Test with a simple SNI extension
        let sni_data = vec![
            0x00, 0x0e, // list length
            0x00, // hostname type
            0x00, 0x0b, // hostname length
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm'
        ];
        
        assert_eq!(parse_sni_extension(&sni_data), Some("example.com".to_string()));
    }
} 