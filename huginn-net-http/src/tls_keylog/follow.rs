//! Reading key log files: once (`KeylogSource::File`) or following appends
//! (`KeylogSource::Follow`) from a background polling thread.

use super::store::{KeyLogStore, MAX_LINE_LEN};
use crate::error::HuginnNetHttpError;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

/// Most bytes read from a followed file per poll, so one huge append can't stall the thread.
const MAX_READ_PER_POLL: u64 = 1024 * 1024;

/// Splits a byte stream into key log lines, enforcing the 512-byte line limit even when a
/// line never ends (FR-019).
#[derive(Default)]
pub(crate) struct LineSplitter {
    partial: Vec<u8>,
    discarding: bool,
}

impl LineSplitter {
    pub(crate) fn feed(&mut self, data: &[u8], store: &KeyLogStore) {
        for chunk in data.split_inclusive(|b| *b == b'\n') {
            let complete = chunk.last() == Some(&b'\n');
            let body = if complete {
                &chunk[..chunk.len().saturating_sub(1)]
            } else {
                chunk
            };
            if self.discarding {
                if complete {
                    self.discarding = false;
                }
                continue;
            }
            if self.partial.len().saturating_add(body.len()) > MAX_LINE_LEN {
                store.count_rejected();
                self.partial.clear();
                self.discarding = !complete;
                continue;
            }
            self.partial.extend_from_slice(body);
            if complete {
                // Rejected lines are counted by the store; the error carries no content.
                let _ = store.insert_line_bytes(&self.partial);
                self.partial.clear();
            }
        }
    }

    /// Handles a final line without a trailing newline (end of a file read once).
    pub(crate) fn finish(&mut self, store: &KeyLogStore) {
        if !self.partial.is_empty() && !self.discarding {
            let _ = store.insert_line_bytes(&self.partial);
        }
        self.partial.clear();
        self.discarding = false;
    }

    fn reset(&mut self) {
        self.partial.clear();
        self.discarding = false;
    }
}

/// Reads a whole key log file into the store.
pub(crate) fn load_file(path: &Path, store: &KeyLogStore) -> Result<(), HuginnNetHttpError> {
    let mut data = Vec::new();
    File::open(path)
        .and_then(|mut f| f.read_to_end(&mut data))
        .map_err(|e| {
            HuginnNetHttpError::Keylog(format!("cannot read {}: {}", path.display(), e.kind()))
        })?;
    let mut splitter = LineSplitter::default();
    splitter.feed(&data, store);
    splitter.finish(store);
    zeroize::Zeroize::zeroize(&mut data);
    Ok(())
}

/// Background thread following a key log file. Stops when dropped.
pub(crate) struct FollowHandle {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FollowHandle {
    pub(crate) fn spawn(
        path: PathBuf,
        store: Arc<KeyLogStore>,
        interval: Duration,
    ) -> Result<Self, HuginnNetHttpError> {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("huginn-keylog-follow".to_string())
            .spawn(move || follow_loop(&path, &store, interval, &thread_stop))
            .map_err(|e| {
                HuginnNetHttpError::Keylog(format!("cannot start key log follower: {}", e.kind()))
            })?;
        Ok(Self { stop, thread: Some(thread) })
    }
}

impl Drop for FollowHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn follow_loop(path: &Path, store: &KeyLogStore, interval: Duration, stop: &AtomicBool) {
    let mut offset: u64 = 0;
    let mut splitter = LineSplitter::default();
    let mut buf = Vec::new();
    while !stop.load(Ordering::Relaxed) {
        if let Ok(mut file) = File::open(path) {
            let len = file.metadata().map(|m| m.len()).unwrap_or(0);
            if len < offset {
                // Truncated or rotated: start over.
                offset = 0;
                splitter.reset();
            }
            if len > offset && file.seek(SeekFrom::Start(offset)).is_ok() {
                buf.clear();
                if let Ok(read) = file.take(MAX_READ_PER_POLL).read_to_end(&mut buf) {
                    offset = offset.saturating_add(u64::try_from(read).unwrap_or(0));
                    splitter.feed(&buf, store);
                }
                zeroize::Zeroize::zeroize(&mut buf);
                // More data may be waiting: poll again right away.
                if len > offset {
                    continue;
                }
            }
        }
        std::thread::sleep(interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let handle = match FollowHandle::spawn(
            path.clone(),
            Arc::clone(&store),
            Duration::from_millis(10),
        ) {
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
}
