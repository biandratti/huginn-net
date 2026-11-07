//! A secret written to the key log after the connection was captured still completes it
//! within the pending window, and not after it (US1-AS3, SC-004).

use super::pcap_util::{keys_path, pcap_dir, read_frames, snapshot};
use huginn_net_http::{HuginnNetHttp, KeyLogStore, KeylogConfig, KeylogSource};
use std::sync::Arc;
use std::time::Duration;

fn analyzer_with_store(timeout: Duration) -> (HuginnNetHttp, Arc<KeyLogStore>) {
    let store = Arc::new(KeyLogStore::new(1000));
    let config =
        KeylogConfig::new(KeylogSource::Store(Arc::clone(&store))).pending_timeout(timeout);
    let analyzer = HuginnNetHttp::new(1000)
        .with_keylog(config)
        .unwrap_or_else(|e| panic!("with_keylog: {e}"));
    (analyzer, store)
}

fn insert_keys(store: &KeyLogStore, keys: &str) {
    for line in keys.lines() {
        store
            .insert_line(line)
            .unwrap_or_else(|e| panic!("key line rejected: {e}"));
    }
}

#[test]
fn secret_arriving_one_second_late_still_completes() {
    let snap = snapshot("akamai-tls13-aes128-chrome");
    let keys = std::fs::read_to_string(keys_path(&snap)).unwrap_or_else(|e| panic!("keys: {e}"));
    let (mut analyzer, store) = analyzer_with_store(Duration::from_secs(2));

    let mut early = Vec::new();
    for frame in read_frames(&pcap_dir().join(&snap.pcap)) {
        early.extend(analyzer.analyze_frame(&frame).and_then(|r| r.http_akamai));
    }
    assert!(early.is_empty(), "nothing can be decrypted before the secret is known");

    std::thread::sleep(Duration::from_secs(1));
    insert_keys(&store, &keys);
    let late: Vec<_> = analyzer
        .sweep_keylog_pending()
        .into_iter()
        .filter_map(|r| r.http_akamai)
        .collect();
    assert_eq!(late.len(), 1);
    assert_eq!(late[0].fingerprint.fingerprint, snap.connections[0].fingerprint);
    assert_eq!(analyzer.keylog_stats().decrypted, 1);
}

#[test]
fn secret_arriving_after_the_timeout_is_ignored() {
    let snap = snapshot("akamai-tls13-aes128-chrome");
    let keys = std::fs::read_to_string(keys_path(&snap)).unwrap_or_else(|e| panic!("keys: {e}"));
    let (mut analyzer, store) = analyzer_with_store(Duration::from_millis(200));

    for frame in read_frames(&pcap_dir().join(&snap.pcap)) {
        let _ = analyzer.analyze_frame(&frame);
    }
    std::thread::sleep(Duration::from_millis(500));
    // The periodic check runs before the secret shows up and drops the connection.
    assert!(analyzer.sweep_keylog_pending().is_empty());
    insert_keys(&store, &keys);
    assert!(analyzer.sweep_keylog_pending().is_empty());
    let stats = analyzer.keylog_stats();
    assert_eq!(stats.no_secret, 1);
    assert_eq!(stats.decrypted, 0);
}
