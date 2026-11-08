//! Secrets and decrypted bytes never show up in results, Debug output or logs.

use super::pcap_util::{keys_config, keys_path, pcap_dir, run_all, secrets_in, snapshot};
use huginn_net_http::{KeyLogStore, KeylogConfig, KeylogSource};
use std::io::Write;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(mut out) = self.0.lock() {
            out.extend_from_slice(buf);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn no_secret_or_plaintext_in_any_produced_text() {
    let captured = Captured(Arc::new(Mutex::new(Vec::new())));
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();

    let mut produced = String::new();
    let mut secrets = Vec::new();
    tracing::subscriber::with_default(subscriber, || {
        for name in ["akamai-tls13-aes128-chrome", "akamai-tls12-aes128-curl"] {
            let snap = snapshot(name);
            secrets.extend(secrets_in(&keys_path(&snap)));
            let (results, stats) = run_all(&pcap_dir().join(&snap.pcap), Some(keys_config(&snap)));
            assert_eq!(stats.decrypted, 1);
            for r in &results {
                produced.push_str(&format!("{r:?}\n"));
                if let Some(a) = &r.http_akamai {
                    produced.push_str(&format!("{a}\n"));
                }
            }
            produced.push_str(&format!("{stats:?}\n{:?}\n", keys_config(&snap)));
        }
        let store = KeyLogStore::new(4);
        let _ =
            store.insert_line(&format!("CLIENT_RANDOM {} {}", "11".repeat(32), "22".repeat(48)));
        let bad =
            store.insert_line(&format!("CLIENT_RANDOM {} {}", "11".repeat(32), "33".repeat(40)));
        produced.push_str(&format!("{store:?}\n{bad:?}\n"));
        secrets.push("33".repeat(40));
        let config = KeylogConfig::new(KeylogSource::Store(Arc::new(store)));
        produced.push_str(&format!("{config:?}\n"));
    });

    let logs = captured
        .0
        .lock()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let all = format!("{produced}\n{logs}").to_lowercase();
    assert!(!secrets.is_empty());
    for secret in &secrets {
        assert!(!all.contains(secret.as_str()), "a key log secret leaked into output or logs");
    }
    for fragment in ["pri * http/2.0", "localhost:8443", "huginn-fixture"] {
        assert!(!all.contains(fragment), "decrypted plaintext leaked: {fragment}");
    }
}
