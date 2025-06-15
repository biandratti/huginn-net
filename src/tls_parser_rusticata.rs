use crate::tls::{TlsSignature, TlsVersion};
use crate::error::PassiveTcpError;
use tls_parser::{
    parse_tls_plaintext, TlsMessage, TlsMessageHandshake,
    TlsClientHelloContents, TlsVersion as RusticataTlsVersion
};
use tracing::{debug};

/// GREASE values that should be filtered out for JA4
const GREASE_VALUES: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// Parse TLS packet using rusticata's tls-parser
pub fn parse_tls_client_hello_rusticata(data: &[u8]) -> Result<TlsSignature, PassiveTcpError> {
    debug!("RUSTICATA DEBUG: Starting TLS parsing with {} bytes", data.len());
    debug!("RUSTICATA DEBUG: First 64 bytes: {:02x?}", &data[..std::cmp::min(64, data.len())]);
    
    // Parse TLS record using rusticata
    match parse_tls_plaintext(data) {
        Ok((remaining, tls_record)) => {
            debug!("RUSTICATA DEBUG: Successfully parsed TLS record");
            debug!("RUSTICATA DEBUG: Remaining bytes: {}", remaining.len());
            debug!("RUSTICATA DEBUG: TLS record has {} messages", tls_record.msg.len());
            
            // Look for ClientHello in the messages
            for (i, message) in tls_record.msg.iter().enumerate() {
                debug!("RUSTICATA DEBUG: Message {}: {:?}", i, std::mem::discriminant(message));
                
                if let TlsMessage::Handshake(handshake) = message {
                    debug!("RUSTICATA DEBUG: Found handshake message: {:?}", std::mem::discriminant(handshake));
                    
                    if let TlsMessageHandshake::ClientHello(client_hello) = handshake {
                        debug!("RUSTICATA DEBUG: Found ClientHello message!");
                        debug!("RUSTICATA DEBUG: ClientHello version: 0x{:04x}", client_hello.version.0);
                        debug!("RUSTICATA DEBUG: ClientHello ciphers: {}", client_hello.ciphers.len());
                        debug!("RUSTICATA DEBUG: ClientHello extensions present: {}", client_hello.ext.is_some());
                        if let Some(ext_data) = &client_hello.ext {
                            debug!("RUSTICATA DEBUG: Extension data size: {} bytes", ext_data.len());
                        }
                        
                        return extract_tls_signature_from_client_hello(client_hello);
                    }
                }
            }
            
            debug!("RUSTICATA DEBUG: No ClientHello found in TLS record");
            Err(PassiveTcpError::Parse("No ClientHello found in TLS record".to_string()))
        }
        Err(e) => {
            debug!("RUSTICATA DEBUG: Failed to parse TLS record: {:?}", e);
            Err(PassiveTcpError::Parse(format!("TLS parsing failed: {:?}", e)))
        }
    }
}

fn extract_tls_signature_from_client_hello(
    client_hello: &TlsClientHelloContents,
) -> Result<TlsSignature, PassiveTcpError> {
    debug!("Extracting TLS signature from ClientHello");
    
    // Parse extensions first to get the real TLS version
    let (extensions, sni, alpn, signature_algorithms, elliptic_curves) = 
        parse_extensions_from_client_hello(client_hello);
    
    // Convert TLS version - check supported_versions extension first
    let version = determine_tls_version(&client_hello.version, &extensions);
    debug!("TLS version: {:?}", version);
    
    // Extract cipher suites (filter GREASE)
    let cipher_suites: Vec<u16> = client_hello.ciphers
        .iter()
        .map(|c| c.0)
        .filter(|&cipher| !GREASE_VALUES.contains(&cipher))
        .collect();
    debug!("Cipher suites (filtered): {} - {:04x?}", cipher_suites.len(), cipher_suites);
    
    let elliptic_curve_point_formats = Vec::new(); // Not commonly used in modern TLS
    
    debug!("Extensions (filtered): {} - {:04x?}", extensions.len(), extensions);
    debug!("SNI: {:?}", sni);
    debug!("ALPN: {:?}", alpn);
    debug!("Signature algorithms: {} - {:04x?}", signature_algorithms.len(), signature_algorithms);
    
    // Debug comparison with expected values
    let expected_ciphers = vec![
        0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303, 
        0xc009, 0xc00a, 0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f, 
        0xc030, 0xcca8, 0xcca9
    ];
    let expected_extensions = vec![
        0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0010, 0x0012, 
        0x0017, 0x001b, 0x001c, 0x0022, 0x0023, 0x002b, 0x002d, 
        0x0033, 0xfe0d, 0xff01
    ];
    
    // Compare results
    let missing_ciphers: Vec<_> = expected_ciphers.iter()
        .filter(|&c| !cipher_suites.contains(c))
        .collect();
    let extra_ciphers: Vec<_> = cipher_suites.iter()
        .filter(|&c| !expected_ciphers.contains(c))
        .collect();
    
    if !missing_ciphers.is_empty() {
        debug!("RUSTICATA - Missing cipher suites: {:04x?}", missing_ciphers);
    }
    if !extra_ciphers.is_empty() {
        debug!("RUSTICATA - Extra cipher suites: {:04x?}", extra_ciphers);
    }
    
    let missing_extensions: Vec<_> = expected_extensions.iter()
        .filter(|&e| !extensions.contains(e))
        .collect();
    let extra_extensions: Vec<_> = extensions.iter()
        .filter(|&e| !expected_extensions.contains(e))
        .collect();
    
    if !missing_extensions.is_empty() {
        debug!("RUSTICATA - Missing extensions: {:04x?}", missing_extensions);
    }
    if !extra_extensions.is_empty() {
        debug!("RUSTICATA - Extra extensions: {:04x?}", extra_extensions);
    }
    
    debug!("RUSTICATA - Cipher suites count: {} (expected: 17)", cipher_suites.len());
    debug!("RUSTICATA - Extensions count: {} (expected: 17)", extensions.len());
    debug!("RUSTICATA - Signature algorithms count: {} (expected: 11)", signature_algorithms.len());
    
    Ok(TlsSignature {
        version,
        cipher_suites,
        extensions,
        elliptic_curves,
        elliptic_curve_point_formats,
        signature_algorithms,
        sni,
        alpn,
    })
}

fn determine_tls_version(legacy_version: &RusticataTlsVersion, extensions: &[u16]) -> TlsVersion {
    // In TLS 1.3, the ClientHello legacy_version field is always 0x0303 (TLS 1.2)
    // The real version is indicated in the supported_versions extension (0x002b)
    
    debug!("Determining TLS version: legacy_version=0x{:04x}, extensions={:04x?}", legacy_version.0, extensions);
    
    // Check for supported_versions extension (0x002b) which indicates TLS 1.3
    if extensions.contains(&0x002b) {
        debug!("Found supported_versions extension (0x002b), this is TLS 1.3");
        return TlsVersion::V1_3;
    }
    
    // Check for TLS 1.3 specific extensions as additional indicators
    let tls13_indicators = [
        0x0033, // key_share
        0x002b, // supported_versions (already checked above)
        0x0029, // pre_shared_key
        0x002a, // early_data
        0x002c, // supported_versions (server)
        0x002d, // cookie
        0x002e, // certificate_authorities
        0x002f, // oid_filters
        0x0030, // post_handshake_auth
    ];
    
    let tls13_ext_count = extensions.iter()
        .filter(|&ext| tls13_indicators.contains(ext))
        .count();
    
    if tls13_ext_count >= 2 {
        debug!("Found {} TLS 1.3 indicator extensions, assuming TLS 1.3", tls13_ext_count);
        return TlsVersion::V1_3;
    }
    
    // Fall back to legacy version
    let version_u16 = legacy_version.0;
    debug!("Using legacy TLS version: 0x{:04x}", version_u16);
    
    match version_u16 {
        0x0304 => TlsVersion::V1_3,
        0x0303 => TlsVersion::V1_2,
        0x0302 => TlsVersion::V1_1,
        0x0301 => TlsVersion::V1_0,
        _ => {
            debug!("Unknown TLS version 0x{:04x}, defaulting to TLS 1.2", version_u16);
            TlsVersion::V1_2
        }
    }
}

fn parse_extensions_from_client_hello(
    client_hello: &TlsClientHelloContents,
) -> (Vec<u16>, Option<String>, Option<String>, Vec<u16>, Vec<u16>) {
    let mut extensions = Vec::new();
    let mut sni = None;
    let mut alpn = None;
    let mut signature_algorithms = Vec::new();
    let mut elliptic_curves = Vec::new();
    
    debug!("RUSTICATA DEBUG: Parsing extensions from ClientHello");
    debug!("RUSTICATA DEBUG: ClientHello has ext field: {:?}", client_hello.ext.is_some());
    
    // Check if extensions are available
    if let Some(ext_data) = &client_hello.ext {
        debug!("RUSTICATA DEBUG: Extension data length: {} bytes", ext_data.len());
        debug!("RUSTICATA DEBUG: First 32 bytes of ext_data: {:02x?}", &ext_data[..std::cmp::min(32, ext_data.len())]);
        
        let (parsed_extensions, parsed_sni, parsed_alpn, parsed_sig_algs, parsed_curves) = 
            parse_extensions_from_raw_detailed(ext_data);
        
        extensions = parsed_extensions;
        sni = parsed_sni;
        alpn = parsed_alpn;
        signature_algorithms = parsed_sig_algs;
        elliptic_curves = parsed_curves;
        
        debug!("RUSTICATA DEBUG: Parsed {} extensions from ext_data", extensions.len());
    } else {
        debug!("RUSTICATA DEBUG: No extension data found in ClientHello.ext field");
        
        // Let's also debug other fields to understand the structure
        debug!("RUSTICATA DEBUG: ClientHello version: 0x{:04x}", client_hello.version.0);
        debug!("RUSTICATA DEBUG: ClientHello ciphers count: {}", client_hello.ciphers.len());
        debug!("RUSTICATA DEBUG: ClientHello random length: {}", client_hello.random.len());
        debug!("RUSTICATA DEBUG: ClientHello session_id: {:?}", client_hello.session_id.map(|s| s.len()));
        debug!("RUSTICATA DEBUG: ClientHello comp count: {}", client_hello.comp.len());
    }
    
    (extensions, sni, alpn, signature_algorithms, elliptic_curves)
}

/// Parse extensions from raw extension data with detailed extraction
fn parse_extensions_from_raw_detailed(ext_data: &[u8]) -> (Vec<u16>, Option<String>, Option<String>, Vec<u16>, Vec<u16>) {
    let mut extensions = Vec::new();
    let mut sni = None;
    let mut alpn = None;
    let mut signature_algorithms = Vec::new();
    let mut elliptic_curves = Vec::new();
    let mut offset = 0;
    
    debug!("Parsing extensions from {} bytes of raw data: {:02x?}", ext_data.len(), &ext_data[..std::cmp::min(32, ext_data.len())]);
    
    // IMPORTANT: rusticata already parsed and removed the extensions length field
    // The ext_data starts directly with the first extension type
    let extensions_end = ext_data.len();
    
    debug!("Processing extensions data, total available: {} bytes", extensions_end);
    
    // Parse individual extensions
    while offset + 4 <= extensions_end {
        let extension_type = u16::from_be_bytes([ext_data[offset], ext_data[offset + 1]]);
        let extension_length = u16::from_be_bytes([ext_data[offset + 2], ext_data[offset + 3]]) as usize;
        offset += 4;
        
        debug!("Found extension: type=0x{:04x}, length={}, offset={}, end={}", 
               extension_type, extension_length, offset, extensions_end);
        
        // Validate extension length
        if offset + extension_length > extensions_end {
            debug!("Extension 0x{:04x} length ({}) extends beyond data boundary (offset={}, end={})", 
                   extension_type, extension_length, offset, extensions_end);
            break;
        }
        
        let extension_data = &ext_data[offset..offset + extension_length];
        
        // Filter GREASE extensions
        if !GREASE_VALUES.contains(&extension_type) {
            extensions.push(extension_type);
            debug!("Added extension 0x{:04x} to list", extension_type);
        } else {
            debug!("Filtered GREASE extension 0x{:04x}", extension_type);
        }
        
        // Parse specific extensions
        match extension_type {
            0x0000 => { // Server Name Indication (SNI)
                if let Some(parsed_sni) = parse_sni_extension(extension_data) {
                    sni = Some(parsed_sni);
                    debug!("Parsed SNI: {:?}", sni);
                }
            }
            0x0010 => { // Application-Layer Protocol Negotiation (ALPN)
                if let Some(parsed_alpn) = parse_alpn_extension(extension_data) {
                    alpn = Some(parsed_alpn);
                    debug!("Parsed ALPN: {:?}", alpn);
                }
            }
            0x000d => { // Signature Algorithms
                let parsed_sig_algs = parse_signature_algorithms_extension(extension_data);
                if !parsed_sig_algs.is_empty() {
                    signature_algorithms = parsed_sig_algs;
                    debug!("Parsed {} signature algorithms: {:04x?}", signature_algorithms.len(), signature_algorithms);
                }
            }
            0x000a => { // Supported Groups (Elliptic Curves)
                let parsed_curves = parse_supported_groups_extension(extension_data);
                if !parsed_curves.is_empty() {
                    elliptic_curves = parsed_curves;
                    debug!("Parsed {} elliptic curves: {:04x?}", elliptic_curves.len(), elliptic_curves);
                }
            }
            // Debug problematic extensions
            0x44cd => {
                debug!("PROBLEMATIC: Found extension 0x44cd (len={}), data: {:02x?}", extension_length, &extension_data[..std::cmp::min(16, extension_data.len())]);
            }
            0x0029 => {
                debug!("PROBLEMATIC: Found extension 0x0029 (pre_shared_key, len={}), data: {:02x?}", extension_length, &extension_data[..std::cmp::min(16, extension_data.len())]);
            }
            0x001c => {
                debug!("EXPECTED: Found extension 0x001c (cert_type, len={}), data: {:02x?}", extension_length, &extension_data[..std::cmp::min(16, extension_data.len())]);
            }
            0x0022 => {
                debug!("EXPECTED: Found extension 0x0022 (cert_status_type, len={}), data: {:02x?}", extension_length, &extension_data[..std::cmp::min(16, extension_data.len())]);
            }
            _ => {
                // Other extensions - just record the type
                debug!("Extension 0x{:04x} recorded but not parsed in detail (len={})", extension_type, extension_length);
            }
        }
        
        offset += extension_length;
    }
    
    // Debug the final extension list and compare with expected
    let expected_extensions = vec![
        0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0010, 0x0012, 
        0x0017, 0x001b, 0x001c, 0x0022, 0x0023, 0x002b, 0x002d, 
        0x0033, 0xfe0d, 0xff01
    ];
    
    debug!("Parsed {} total extensions: {:04x?}", extensions.len(), extensions);
    debug!("Expected {} extensions: {:04x?}", expected_extensions.len(), expected_extensions);
    
    let missing_extensions: Vec<_> = expected_extensions.iter()
        .filter(|&e| !extensions.contains(e))
        .collect();
    let extra_extensions: Vec<_> = extensions.iter()
        .filter(|&e| !expected_extensions.contains(e))
        .collect();
    
    if !missing_extensions.is_empty() {
        debug!("ANALYSIS: Missing expected extensions: {:04x?}", missing_extensions);
    }
    if !extra_extensions.is_empty() {
        debug!("ANALYSIS: Extra extensions found: {:04x?}", extra_extensions);
    }
    
    debug!("Final SNI: {:?}, ALPN: {:?}", sni, alpn);
    debug!("Signature algorithms: {} items: {:04x?}", signature_algorithms.len(), signature_algorithms);
    debug!("Elliptic curves: {} items: {:04x?}", elliptic_curves.len(), elliptic_curves);
    
    (extensions, sni, alpn, signature_algorithms, elliptic_curves)
}

/// Parse SNI extension
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }
    
    let mut offset = 0;
    
    // Server name list length (2 bytes)
    let list_length = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;
    
    if offset + list_length > data.len() {
        return None;
    }
    
    // Parse first server name entry
    if offset + 3 <= data.len() {
        let name_type = data[offset]; // Should be 0 for hostname
        offset += 1;
        
        if name_type == 0 {
            let name_length = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            
            if offset + name_length <= data.len() {
                let hostname = String::from_utf8_lossy(&data[offset..offset + name_length]);
                return Some(hostname.to_string());
            }
        }
    }
    
    None
}

/// Parse ALPN extension
fn parse_alpn_extension(data: &[u8]) -> Option<String> {
    if data.len() < 3 {
        return None;
    }
    
    let mut offset = 0;
    
    // Protocol name list length (2 bytes)
    let list_length = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;
    
    if offset + list_length > data.len() {
        return None;
    }
    
    // Parse first protocol name
    if offset < data.len() {
        let protocol_length = data[offset] as usize;
        offset += 1;
        
        if offset + protocol_length <= data.len() {
            let protocol = String::from_utf8_lossy(&data[offset..offset + protocol_length]);
            return Some(protocol.to_string());
        }
    }
    
    None
}

/// Parse signature algorithms extension
fn parse_signature_algorithms_extension(data: &[u8]) -> Vec<u16> {
    let mut algorithms = Vec::new();
    
    if data.len() < 2 {
        debug!("Signature algorithms extension too short");
        return algorithms;
    }
    
    let mut offset = 0;
    
    // Signature algorithms length (2 bytes)
    let list_length = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;
    
    debug!("Signature algorithms list length: {}, available data: {}", list_length, data.len() - 2);
    
    if offset + list_length > data.len() {
        debug!("Signature algorithms list extends beyond data boundary");
        return algorithms;
    }
    
    let list_end = offset + list_length;
    
    // Parse signature algorithms (2 bytes each)
    while offset + 2 <= list_end {
        let algorithm = u16::from_be_bytes([data[offset], data[offset + 1]]);
        algorithms.push(algorithm);
        debug!("Found signature algorithm: 0x{:04x}", algorithm);
        offset += 2;
    }
    
    debug!("Parsed {} signature algorithms total", algorithms.len());
    algorithms
}

/// Parse supported groups (elliptic curves) extension
fn parse_supported_groups_extension(data: &[u8]) -> Vec<u16> {
    let mut groups = Vec::new();
    
    if data.len() < 2 {
        debug!("Supported groups extension too short");
        return groups;
    }
    
    let mut offset = 0;
    
    // Supported groups length (2 bytes)
    let list_length = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;
    
    debug!("Supported groups list length: {}, available data: {}", list_length, data.len() - 2);
    
    if offset + list_length > data.len() {
        debug!("Supported groups list extends beyond data boundary");
        return groups;
    }
    
    let list_end = offset + list_length;
    
    // Parse supported groups (2 bytes each)
    while offset + 2 <= list_end {
        let group = u16::from_be_bytes([data[offset], data[offset + 1]]);
        groups.push(group);
        debug!("Found supported group: 0x{:04x}", group);
        offset += 2;
    }
    
    debug!("Parsed {} supported groups total", groups.len());
    groups
}

/// Parse extensions from raw extension data (simplified version for backward compatibility)
fn parse_extensions_from_raw(ext_data: &[u8]) -> Vec<u16> {
    let (extensions, _, _, _, _) = parse_extensions_from_raw_detailed(ext_data);
    extensions
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_grease_filtering() {
        let test_ciphers = vec![0x1301, 0x0a0a, 0x1302, 0x1a1a, 0xc02f];
        let filtered: Vec<u16> = test_ciphers.into_iter()
            .filter(|&cipher| !GREASE_VALUES.contains(&cipher))
            .collect();
        
        assert_eq!(filtered, vec![0x1301, 0x1302, 0xc02f]);
    }
    
    #[test]
    fn test_tls_version_conversion() {
        let tls13 = RusticataTlsVersion(0x0304);
        let tls12 = RusticataTlsVersion(0x0303);
        
        assert_eq!(determine_tls_version(&tls13, &[]), TlsVersion::V1_3);
        assert_eq!(determine_tls_version(&tls12, &[]), TlsVersion::V1_2);
    }
} 