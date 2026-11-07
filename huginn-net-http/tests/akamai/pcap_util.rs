//! Helpers to read, rewrite and replay the generated key log fixtures.
//!
//! The fixtures use Ethernet + IPv4 (20 byte header) + TCP (20 byte header), so the TCP
//! payload always starts at byte 54.

use huginn_net_http::{
    AkamaiOutput, HttpAnalysisResult, HuginnNetHttp, KeylogConfig, KeylogSource, KeylogStats,
};
use pcap_file::pcap::{PcapPacket, PcapReader, PcapWriter};
use serde::Deserialize;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

const PAYLOAD_OFFSET: usize = 54;
const CLIENT_IP: [u8; 4] = [10, 0, 0, 2];

#[derive(Deserialize)]
pub struct Snapshot {
    pub pcap: String,
    pub keys: Option<String>,
    pub connections: Vec<Expected>,
    pub not_http2: u64,
}

#[derive(Deserialize)]
pub struct Expected {
    pub source: Endpoint,
    pub destination: Endpoint,
    pub tls_version: Option<String>,
    pub cipher_suite: Option<u16>,
    pub fingerprint: String,
    pub hash: String,
}

#[derive(Deserialize)]
pub struct Endpoint {
    pub ip: String,
    pub port: u16,
}

pub fn snapshot(name: &str) -> Snapshot {
    let path = format!("tests/snapshots/{name}.pcap.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

pub fn pcap_dir() -> PathBuf {
    Path::new("..").join("pcap")
}

pub fn keys_path(snap: &Snapshot) -> PathBuf {
    pcap_dir().join(
        snap.keys
            .as_deref()
            .unwrap_or_else(|| panic!("fixture has no key log")),
    )
}

pub fn keys_config(snap: &Snapshot) -> KeylogConfig {
    KeylogConfig::new(KeylogSource::File(keys_path(snap)))
}

/// A unique scratch directory for one test.
pub fn scratch_dir(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("huginn-{test}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("create {}: {e}", dir.display()));
    dir
}

pub fn read_frames(path: &Path) -> Vec<Vec<u8>> {
    let file = File::open(path).unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
    let mut reader = PcapReader::new(file).unwrap_or_else(|e| panic!("pcap reader: {e}"));
    let mut frames = Vec::new();
    while let Some(packet) = reader.next_packet() {
        let packet = packet.unwrap_or_else(|e| panic!("pcap packet: {e}"));
        frames.push(packet.data.to_vec());
    }
    frames
}

pub fn write_frames(frames: &[Vec<u8>], path: &Path) {
    let file = File::create(path).unwrap_or_else(|e| panic!("create {}: {e}", path.display()));
    let mut writer = PcapWriter::new(file).unwrap_or_else(|e| panic!("pcap writer: {e}"));
    for (i, frame) in frames.iter().enumerate() {
        let ts = Duration::from_millis(u64::try_from(i).unwrap_or(0));
        let len = u32::try_from(frame.len()).unwrap_or(u32::MAX);
        writer
            .write_packet(&PcapPacket::new(ts, len, frame))
            .unwrap_or_else(|e| panic!("write packet: {e}"));
    }
}

pub fn is_client(frame: &[u8]) -> bool {
    frame.get(26..30) == Some(&CLIENT_IP[..])
}

pub fn payload(frame: &[u8]) -> &[u8] {
    frame.get(PAYLOAD_OFFSET..).unwrap_or(&[])
}

pub fn seq(frame: &[u8]) -> u32 {
    match frame.get(38..42) {
        Some(b) => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        None => panic!("frame too short for a TCP header"),
    }
}

/// The same frame with a new TCP sequence number and payload (IPv4 total length updated).
pub fn with_payload(frame: &[u8], seq: u32, data: &[u8]) -> Vec<u8> {
    let mut out = frame[..PAYLOAD_OFFSET].to_vec();
    out[38..42].copy_from_slice(&seq.to_be_bytes());
    let total = u16::try_from(40usize.saturating_add(data.len())).unwrap_or(u16::MAX);
    out[16..18].copy_from_slice(&total.to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Indices of client frames that carry payload, in capture order.
pub fn client_data_indices(frames: &[Vec<u8>]) -> Vec<usize> {
    (0..frames.len())
        .filter(|&i| is_client(&frames[i]) && !payload(&frames[i]).is_empty())
        .collect()
}

/// Indices of server frames that carry payload, in capture order.
pub fn server_data_indices(frames: &[Vec<u8>]) -> Vec<usize> {
    (0..frames.len())
        .filter(|&i| !is_client(&frames[i]) && !payload(&frames[i]).is_empty())
        .collect()
}

/// Runs a capture through a sequential analyzer and returns the Akamai results and counters.
pub fn run(pcap: &Path, keylog: Option<KeylogConfig>) -> (Vec<AkamaiOutput>, KeylogStats) {
    let (results, stats) = run_all(pcap, keylog);
    (results.into_iter().filter_map(|r| r.http_akamai).collect(), stats)
}

/// Like [`run`] but returns every analysis result.
pub fn run_all(
    pcap: &Path,
    keylog: Option<KeylogConfig>,
) -> (Vec<HttpAnalysisResult>, KeylogStats) {
    let mut analyzer = HuginnNetHttp::new(1000);
    if let Some(config) = keylog {
        analyzer = analyzer
            .with_keylog(config)
            .unwrap_or_else(|e| panic!("with_keylog: {e}"));
    }
    let (tx, rx) = mpsc::channel::<HttpAnalysisResult>();
    let path = pcap.to_str().unwrap_or_else(|| panic!("non UTF-8 path"));
    analyzer
        .analyze_pcap(path, tx, None)
        .unwrap_or_else(|e| panic!("analyze_pcap: {e}"));
    (rx.try_iter().collect(), analyzer.keylog_stats())
}

/// All secret values (third field) of a key log file, lowercase hex.
pub fn secrets_in(keys: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(keys).unwrap_or_else(|e| panic!("read keys: {e}"));
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_whitespace().nth(2))
        .map(str::to_lowercase)
        .collect()
}
