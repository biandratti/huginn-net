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
use zeroize::Zeroize;

/// Most bytes read from a followed file per poll, so one huge append can't stall the thread.
const MAX_READ_PER_POLL: u64 = 1024 * 1024;

/// Splits a byte stream into key log lines, enforcing the 512-byte line limit even when a
/// line never ends.
pub struct LineSplitter {
    /// The line being assembled. It holds a secret, so it is wiped instead of just cleared,
    /// and reserved up front so it never reallocates.
    partial: Vec<u8>,
    discarding: bool,
}

impl Default for LineSplitter {
    fn default() -> Self {
        Self { partial: Vec::with_capacity(MAX_LINE_LEN), discarding: false }
    }
}

impl Drop for LineSplitter {
    fn drop(&mut self) {
        self.partial.zeroize();
    }
}

impl LineSplitter {
    pub fn feed(&mut self, data: &[u8], store: &KeyLogStore) {
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
                self.wipe_partial();
                self.discarding = !complete;
                continue;
            }
            self.partial.extend_from_slice(body);
            if complete {
                // Rejected lines are counted by the store; the error carries no content.
                let _ = store.insert_line_bytes(&self.partial);
                self.wipe_partial();
            }
        }
    }

    /// Handles a final line without a trailing newline (end of a file read once).
    pub fn finish(&mut self, store: &KeyLogStore) {
        if !self.partial.is_empty() && !self.discarding {
            let _ = store.insert_line_bytes(&self.partial);
        }
        self.wipe_partial();
        self.discarding = false;
    }

    fn reset(&mut self) {
        self.wipe_partial();
        self.discarding = false;
    }

    /// Wipes the bytes of the line and keeps the allocation.
    fn wipe_partial(&mut self) {
        self.partial.as_mut_slice().zeroize();
        self.partial.clear();
    }
}

/// Reads a whole key log file into the store.
pub fn load_file(path: &Path, store: &KeyLogStore) -> Result<(), HuginnNetHttpError> {
    // Sized up front so reading does not reallocate and leave unwiped copies of secrets.
    let mut data = Vec::new();
    File::open(path)
        .and_then(|mut f| {
            let len = f.metadata().map(|m| m.len()).unwrap_or(0);
            data.reserve_exact(usize::try_from(len).unwrap_or(0).saturating_add(1));
            f.read_to_end(&mut data)
        })
        .map_err(|e| {
            HuginnNetHttpError::Keylog(format!("cannot read {}: {}", path.display(), e.kind()))
        })?;
    let mut splitter = LineSplitter::default();
    splitter.feed(&data, store);
    splitter.finish(store);
    data.zeroize();
    Ok(())
}

/// Background thread following a key log file. Stops when dropped.
pub struct FollowHandle {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FollowHandle {
    pub fn spawn(
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
    // Reserved once so reads never reallocate and leave unwiped copies of secrets.
    let mut buf = Vec::with_capacity(usize::try_from(MAX_READ_PER_POLL).unwrap_or(0));
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
                buf.as_mut_slice().zeroize();
                // More data may be waiting: poll again right away.
                if len > offset {
                    continue;
                }
            }
        }
        std::thread::sleep(interval);
    }
}
