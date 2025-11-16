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
use tracing::debug;

pub fn process_tls_ipv4(packet: &Ipv4Packet) -> Result<ObservableTlsPackage, HuginnNetTlsError> {
    if packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return Err(HuginnNetTlsError::UnsupportedProtocol("IPv4".to_string()));
    }

    if let Some(tcp) = TcpPacket::new(packet.payload()) {
        process_tls_tcp(&tcp)
    } else {
        Ok(ObservableTlsPackage { tls_client: None })
    }
}

pub fn process_tls_ipv6(packet: &Ipv6Packet) -> Result<ObservableTlsPackage, HuginnNetTlsError> {
    if packet.get_next_header() != IpNextHeaderProtocols::Tcp {
        return Err(HuginnNetTlsError::UnsupportedProtocol("IPv6".to_string()));
    }

    if let Some(tcp) = TcpPacket::new(packet.payload()) {
        process_tls_tcp(&tcp)
    } else {
        Ok(ObservableTlsPackage { tls_client: None })
    }
}

pub fn process_tls_tcp(tcp: &TcpPacket) -> Result<ObservableTlsPackage, HuginnNetTlsError> {
    let payload = tcp.payload();

    if !is_tls_traffic(payload) {
        return Ok(ObservableTlsPackage { tls_client: None });
    }

    parse_tls_client_hello(payload)
        .map(|signature| {
            let ja4 = signature.generate_ja4();
            let ja4_original = signature.generate_ja4_original();
            ObservableTlsPackage {
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
            }
        })
        .or(Ok(ObservableTlsPackage { tls_client: None }))
}

/// Detect TLS traffic based on packet content only
/// This is more reliable than port-based detection since TLS can run on any port
#[inline(always)]
pub fn is_tls_traffic(payload: &[u8]) -> bool {
    // Check for TLS record header (0x16 = Handshake, followed by version)
    payload.len() >= 5 && payload[0] == 0x16 && {
        let version = u16::from_be_bytes([payload[1], payload[2]]);
        (0x0300..=0x0304).contains(&version)
    }
}

pub fn parse_tls_client_hello(data: &[u8]) -> Result<Signature, HuginnNetTlsError> {
    match parse_tls_plaintext(data) {
        Ok((_remaining, tls_record)) => {
            for message in tls_record.msg.iter() {
                if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello)) =
                    message
                {
                    return extract_tls_signature_from_client_hello(client_hello);
                }
            }
            Err(HuginnNetTlsError::Parse("No ClientHello found in TLS record".to_string()))
        }
        Err(e) => Err(HuginnNetTlsError::Parse(format!("TLS parsing failed: {e:?}"))),
    }
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
