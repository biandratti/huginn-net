use crate::error::HuginnNetTlsError;
use crate::observable::ObservableTlsClient;
use crate::observable::ObservableTlsPackage;
use crate::tls::{Signature, TlsVersion, TLS_GREASE_VALUES};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use tls_parser::{
    parse_tls_extensions, parse_tls_plaintext, TlsClientHelloContents, TlsExtension,
    TlsExtensionType, TlsMessage, TlsMessageHandshake,
};
use tracing::{debug, error};

pub fn process_tls_ipv4(packet: &Ipv4Packet) -> Result<ObservableTlsPackage, HuginnNetTlsError> {
    if packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        debug!("IPv4 packet with non-TCP protocol: {:?}", packet.get_next_level_protocol());
        return Ok(ObservableTlsPackage { tls_client: None });
    }

    if let Some(tcp) = TcpPacket::new(packet.payload()) {
        process_tls_tcp(&tcp)
    } else {
        debug!("IPv4 packet: Could not parse TCP from payload (len={})", packet.payload().len());
        Ok(ObservableTlsPackage { tls_client: None })
    }
}

pub fn process_tls_ipv6(packet: &Ipv6Packet) -> Result<ObservableTlsPackage, HuginnNetTlsError> {
    if packet.get_next_header() != IpNextHeaderProtocols::Tcp {
        debug!("IPv6 packet with non-TCP protocol: {:?}", packet.get_next_header());
        return Ok(ObservableTlsPackage { tls_client: None });
    }

    if let Some(tcp) = TcpPacket::new(packet.payload()) {
        process_tls_tcp(&tcp)
    } else {
        debug!("IPv6 packet: Could not parse TCP from payload (len={})", packet.payload().len());
        Ok(ObservableTlsPackage { tls_client: None })
    }
}

pub fn process_tls_tcp(tcp: &TcpPacket) -> Result<ObservableTlsPackage, HuginnNetTlsError> {
    let payload = tcp.payload();
    let src_port = tcp.get_source();
    let dst_port = tcp.get_destination();

    if payload.is_empty() {
        debug!("TCP packet {src_port}->{dst_port}: Empty payload, skipping");
        return Ok(ObservableTlsPackage { tls_client: None });
    }

    let first_byte = payload[0];
    let is_tls = is_tls_traffic(payload);

    debug!(
        "TCP packet {src_port}->{dst_port}: payload_len={}, first_byte=0x{:02x}, is_tls={}",
        payload.len(),
        first_byte,
        is_tls
    );

    if !is_tls {
        // Log first few non-TLS packets for debugging
        // Note: This will log multiple times but that's OK for debugging
        if !payload.is_empty() && (payload[0] == 0x17 || payload[0] == 0x15 || payload[0] == 0x14) {
            // These are TLS Application Data, Alert, or Change Cipher Spec - might be interesting
            debug!("Not TLS Handshake but TLS-like: first_byte=0x{:02x}, payload_len={}, first_bytes={:02x?}", 
                   first_byte, payload.len(),
                   payload.get(0..10.min(payload.len())).map(|s| s.to_vec()).unwrap_or_default());
        }
        return Ok(ObservableTlsPackage { tls_client: None });
    }

    debug!("Attempting to parse TLS ClientHello...");
    match parse_tls_client_hello(payload) {
        Ok(Some(signature)) => {
            debug!(
                "Successfully parsed TLS ClientHello! Version={:?}, SNI={:?}, ALPN={:?}",
                signature.version, signature.sni, signature.alpn
            );
            let ja4 = signature.generate_ja4();
            let ja4_original = signature.generate_ja4_original();
            Ok(ObservableTlsPackage {
                tls_client: Some(ObservableTlsClient {
                    version: signature.version,
                    sni: signature.sni,
                    alpn: signature.alpn,
                    cipher_suites: signature.cipher_suites,
                    extensions: signature.extensions,
                    signature_algorithms: signature.signature_algorithms,
                    elliptic_curves: signature.elliptic_curves,
                    ja4,
                    ja4_original,
                }),
            })
        }
        Ok(None) => {
            debug!("No ClientHello found in TLS record, ignoring");
            Ok(ObservableTlsPackage { tls_client: None })
        }
        Err(e) => {
            debug!("Could not parse TLS ClientHello from {src_port}->{dst_port}: {:?}", e);
            debug!(
                "Payload (first 30 bytes): {:02x?}",
                payload
                    .get(0..30.min(payload.len()))
                    .map(|s| s.to_vec())
                    .unwrap_or_default()
            );
            Ok(ObservableTlsPackage { tls_client: None })
        }
    }
}

/// Detect TLS traffic based on packet content only
/// This is more reliable than port-based detection since TLS can run on any port
#[inline(always)]
pub fn is_tls_traffic(payload: &[u8]) -> bool {
    // Check for TLS record header (0x16 = Handshake, followed by version)
    if payload.len() < 5 {
        return false;
    }

    let content_type = payload[0];
    let is_handshake = content_type == 0x16; // TLS Handshake

    if is_handshake {
        let version = u16::from_be_bytes([payload[1], payload[2]]);
        let is_valid_version = (0x0300..=0x0304).contains(&version);
        if is_valid_version {
            debug!(
                "TLS detected: content_type=0x{:02x} (Handshake), version=0x{:04x}",
                content_type, version
            );
        } else {
            debug!(
                "Looks like TLS but invalid version: content_type=0x{:02x}, version=0x{:04x}",
                content_type, version
            );
        }
        return is_valid_version;
    }

    false
}

/// Parse TLS ClientHello from raw bytes
///
/// # Returns
/// - `Ok(Some(Signature))` if ClientHello was found and parsed successfully
/// - `Ok(None)` if TLS record is valid but doesn't contain ClientHello (e.g., ServerHello, Alert)
/// - `Err(HuginnNetTlsError)` if parsing failed
pub fn parse_tls_client_hello(data: &[u8]) -> Result<Option<Signature>, HuginnNetTlsError> {
    debug!("Parsing TLS ClientHello, data_len={}", data.len());

    // Try to extract only the first complete TLS record if data is fragmented
    let data_to_parse = if data.len() >= 5 {
        // Read TLS record length from bytes 3-4
        let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        let needed = record_len.saturating_add(5);

        if data.len() >= needed {
            debug!(
                "Complete TLS record detected: record_len={}, total_available={}",
                record_len,
                data.len()
            );
            &data[..needed]
        } else {
            debug!("Incomplete TLS record: need {} bytes, have {} bytes", needed, data.len());
            data
        }
    } else {
        return Err(HuginnNetTlsError::Parse("Not enough data for TLS record header".to_string()));
    };

    match parse_tls_plaintext(data_to_parse) {
        Ok((remaining, tls_record)) => {
            debug!(
                "TLS record parsed successfully! {} messages, {} bytes remaining",
                tls_record.msg.len(),
                remaining.len()
            );
            for (i, message) in tls_record.msg.iter().enumerate() {
                let msg_type = format!("{:?}", std::mem::discriminant(message));
                debug!("Message {}: {}", i, msg_type);
                if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello)) =
                    message
                {
                    debug!("Found ClientHello message! Extracting signature...");
                    match extract_tls_signature_from_client_hello(client_hello) {
                        Ok(sig) => {
                            debug!("  Signature extracted successfully!");
                            return Ok(Some(sig));
                        }
                        Err(e) => {
                            error!("Failed to extract signature from ClientHello: {:?}", e);
                            return Err(e);
                        }
                    }
                }
            }
            // Not an error - record is valid TLS but doesn't contain ClientHello (e.g., ServerHello, Alert)
            debug!(
                "No ClientHello found in TLS record ({} messages, types: {:?})",
                tls_record.msg.len(),
                tls_record
                    .msg
                    .iter()
                    .map(|m| format!("{:?}", std::mem::discriminant(m)))
                    .collect::<Vec<_>>()
            );
            Ok(None)
        }
        Err(e) => {
            error!("TLS plaintext parsing failed: {:?}", e);
            debug!(
                "Data length: {}, first 50 bytes: {:02x?}",
                data_to_parse.len(),
                data_to_parse
                    .get(0..50.min(data_to_parse.len()))
                    .map(|s| s.to_vec())
                    .unwrap_or_default()
            );
            Err(HuginnNetTlsError::Parse(format!("TLS parsing failed: {e:?}")))
        }
    }
}

/// Parse TLS ClientHello and extract JA4 fingerprint string directly
///
/// This is a convenience function that combines parsing and fingerprint generation
/// into a single call, returning the JA4 fingerprint string directly.
///
/// # Parameters
/// - `data`: Raw TLS ClientHello bytes
///
/// # Returns
/// - `Some(String)` containing the JA4 fingerprint if parsing succeeds
/// - `None` if parsing fails or no ClientHello is found
///
/// # Example
/// ```no_run
/// use huginn_net_tls::tls_process::parse_tls_client_hello_ja4;
///
/// let client_hello_bytes = b"\x16\x03\x01\x00\x4a...";
/// if let Some(ja4) = parse_tls_client_hello_ja4(client_hello_bytes) {
///     println!("JA4 fingerprint: {}", ja4);
/// }
/// ```
#[must_use]
pub fn parse_tls_client_hello_ja4(data: &[u8]) -> Option<String> {
    parse_tls_client_hello(data)
        .ok()
        .flatten()
        .map(|sig| sig.generate_ja4().full.value().to_string())
}

pub fn extract_tls_signature_from_client_hello(
    client_hello: &TlsClientHelloContents,
) -> Result<Signature, HuginnNetTlsError> {
    let cipher_suites: Vec<u16> = client_hello
        .ciphers
        .iter()
        .map(|c| c.0)
        .filter(|&cipher| !TLS_GREASE_VALUES.contains(&cipher))
        .collect();

    let mut extensions = Vec::new();
    let mut sni = None;
    let mut alpn = None;
    let mut signature_algorithms = Vec::new();
    let mut elliptic_curves = Vec::new();
    let mut elliptic_curve_point_formats = Vec::new();

    // Parse extensions if present - if not present, we still generate JA4 with empty extension fields
    if let Some(ext_data) = &client_hello.ext {
        match parse_tls_extensions(ext_data) {
            Ok((_remaining, parsed_extensions)) => {
                for extension in &parsed_extensions {
                    let ext_type: u16 = TlsExtensionType::from(extension).into();

                    // Filter GREASE extensions
                    if !TLS_GREASE_VALUES.contains(&ext_type) {
                        extensions.push(ext_type);
                    }

                    match extension {
                        TlsExtension::SNI(sni_list) => {
                            if let Some((_, hostname)) = sni_list.first() {
                                sni = std::str::from_utf8(hostname).ok().map(str::to_owned);
                            }
                        }
                        TlsExtension::ALPN(alpn_list) => {
                            if let Some(protocol) = alpn_list.first() {
                                alpn = std::str::from_utf8(protocol).ok().map(str::to_owned);
                            }
                        }
                        TlsExtension::SignatureAlgorithms(sig_algs) => {
                            signature_algorithms = sig_algs.clone();
                        }
                        TlsExtension::EllipticCurves(curves) => {
                            elliptic_curves = curves.iter().map(|c| c.0).collect();
                        }
                        TlsExtension::EcPointFormats(formats) => {
                            elliptic_curve_point_formats = formats.to_vec();
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => {
                debug!("Failed to parse TLS extensions: {:?}", e);
            }
        }
    }

    let version = determine_tls_version(&client_hello.version, &extensions);

    Ok(Signature {
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

pub fn determine_tls_version(
    legacy_version: &tls_parser::TlsVersion,
    extensions: &[u16],
) -> TlsVersion {
    // TLS 1.3 uses supported_versions extension
    if extensions.contains(&TlsExtensionType::SupportedVersions.into()) {
        return TlsVersion::V1_3;
    }

    // Parse legacy version from ClientHello
    // Note: SSL 2.0 is not supported by tls-parser (too legacy/vulnerable)
    match *legacy_version {
        tls_parser::TlsVersion::Tls13 => TlsVersion::V1_3,
        tls_parser::TlsVersion::Tls12 => TlsVersion::V1_2,
        tls_parser::TlsVersion::Tls11 => TlsVersion::V1_1,
        tls_parser::TlsVersion::Tls10 => TlsVersion::V1_0,
        tls_parser::TlsVersion::Ssl30 => TlsVersion::Ssl3_0,
        _ => {
            debug!("Unknown/unsupported TLS version {:?}, defaulting to TLS 1.2", legacy_version);
            TlsVersion::V1_2
        }
    }
}
