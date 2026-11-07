use huginn_net_http::KeyLogStore;
use huginn_net_http::keylog_internals::{FollowHandle, LineSplitter};
use std::sync::Arc;
use std::time::Duration;

const LINE: &str =
    "CLIENT_RANDOM 0102030405060708091011121314151617181920212223242526272829303132 ";

fn line(secret_byte: &str) -> String {
    format!("{LINE}{}\n", secret_byte.repeat(48))
}

#[test]
fn splits_lines_across_feeds() {
    let store = KeyLogStore::new(10);
    let mut s = LineSplitter::default();
    let text = line("ab");
    let (a, b) = text.split_at(30);
    s.feed(a.as_bytes(), &store);
    assert!(store.is_empty());
    s.feed(b.as_bytes(), &store);
    assert_eq!(store.len(), 1);
}

#[test]
fn over_long_line_without_newline_is_discarded_and_counted_once() {
    let store = KeyLogStore::new(10);
    let mut s = LineSplitter::default();
    for _ in 0..10 {
        s.feed(&[b'x'; 200], &store);
    }
    assert_eq!(store.lines_rejected(), 1);
    s.feed(b"tail\n", &store);
    s.feed(line("cd").as_bytes(), &store);
    assert_eq!(store.len(), 1, "a valid line after the discarded one is accepted");
    assert_eq!(store.lines_rejected(), 1);
}

#[test]
fn follow_picks_up_appends_and_truncation() {
    use std::io::Write;
    let dir = std::env::temp_dir().join(format!("huginn-follow-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("keys.log");
    let _ = std::fs::write(&path, "# header\n");
    let store = Arc::new(KeyLogStore::new(10));
    let handle =
        match FollowHandle::spawn(path.clone(), Arc::clone(&store), Duration::from_millis(10)) {
            Ok(h) => h,
            Err(e) => panic!("spawn failed: {e}"),
        };
    let append = |text: &str| {
        if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(&path) {
            let _ = f.write_all(text.as_bytes());
        }
    };
    append(&line("11"));
    let wait = |n: usize| {
        for _ in 0..200 {
            if store.len() >= n {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    };
    assert!(wait(1), "appended line must be picked up");
    // Rotation: truncate and write a different client random.
    let rotated = format!("CLIENT_RANDOM {} {}\n", "ff".repeat(32), "22".repeat(48));
    let _ = std::fs::write(&path, rotated);
    assert!(wait(2), "line after truncation must be picked up");
    drop(handle);
    let _ = std::fs::remove_dir_all(&dir);
}
