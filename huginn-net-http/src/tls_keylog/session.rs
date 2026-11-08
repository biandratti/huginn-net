//! Per-connection state machine: reassemble -> read handshake -> wait for secret -> decrypt the
//! start of the client stream -> Akamai fingerprint.

use super::handshake::{ServerHelloInfo, ServerHelloScan, parse_client_hello, parse_server_hello};
use super::record::{
    CT_ALERT, CT_APPLICATION_DATA, CT_CHANGE_CIPHER_SPEC, CT_HANDSHAKE, CipherSuite, RawRecord,
    RecordDecryptor, RecordError, next_record,
};
use super::schedule::{tls12_client_keys, tls13_traffic_keys};
use super::store::{KeyEntry, KeyLogStore};
use crate::akamai::AkamaiFingerprint;
use crate::akamai::pipeline::{AccumulatorError, AkamaiAccumulator};
use crate::output::TlsVersion;
use crate::process::reassembly::StreamReassembler;
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// TLS 1.3 records tried with the application key at sequence number 0. The client's
/// encrypted handshake records come first and fail to open; the first one that opens is the
/// first application record. Trying is cheaper than deriving the handshake keys, which are
/// only used when this budget runs out (e.g. a large client certificate).
const TLS13_TRIAL_RECORDS: usize = 4;
/// TLS 1.3 handshake message type of Finished.
const HS_FINISHED: u8 = 20;

/// Why a session ended without a fingerprint. Each maps to one `KeylogStats` counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Abandon {
    NoSecret,
    Unsupported,
    AuthFailed,
    Reassembly,
    NotHttp2,
    Malformed,
}

#[derive(Debug)]
pub(crate) enum Step {
    Pending,
    Done {
        fingerprint: AkamaiFingerprint,
        version: TlsVersion,
        cipher_suite: u16,
    },
    Abandoned(Abandon),
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SessionLimits {
    pub(crate) pending_timeout: Duration,
    pub(crate) max_client_buffer: usize,
    pub(crate) max_server_buffer: usize,
}

enum Phase {
    /// No decryptor yet: waiting for the ServerHello and/or the secret.
    AwaitKeys,
    /// TLS 1.3, decrypting client handshake records until Finished.
    Tls13Handshake {
        hs: RecordDecryptor,
        app: RecordDecryptor,
    },
    /// TLS 1.3: trying the app key on the first records. Records that fail are kept while a
    /// handshake secret is known, so they can be replayed with the handshake key.
    Tls13Trial {
        app: Box<RecordDecryptor>,
        tried: usize,
        skipped: Vec<RawRecord>,
        hs_secret: Option<Zeroizing<Vec<u8>>>,
    },
    /// TLS 1.2: next record must be the encrypted client Finished (seq 0).
    Tls12Finished { dec: RecordDecryptor },
    /// Decrypting application data.
    App { dec: RecordDecryptor },
}

pub(crate) struct TlsSession {
    client_stream: StreamReassembler,
    server_stream: Option<StreamReassembler>,
    client_hs: Vec<u8>,
    server_hs: Vec<u8>,
    client_random: Option<[u8; 32]>,
    server_hello: Option<ServerHelloInfo>,
    suite: Option<CipherSuite>,
    client_ccs_seen: bool,
    encrypted: VecDeque<RawRecord>,
    encrypted_bytes: usize,
    phase: Phase,
    akamai: AkamaiAccumulator,
    limits: SessionLimits,
    deadline: Option<Instant>,
}

impl TlsSession {
    pub(crate) fn new(limits: SessionLimits) -> Self {
        Self {
            client_stream: StreamReassembler::new(limits.max_client_buffer),
            server_stream: Some(StreamReassembler::new(limits.max_server_buffer)),
            client_hs: Vec::new(),
            server_hs: Vec::new(),
            client_random: None,
            server_hello: None,
            suite: None,
            client_ccs_seen: false,
            encrypted: VecDeque::new(),
            encrypted_bytes: 0,
            phase: Phase::AwaitKeys,
            akamai: AkamaiAccumulator::new(limits.max_client_buffer),
            limits,
            deadline: None,
        }
    }

    pub(crate) fn client_random(&self) -> Option<&[u8; 32]> {
        self.client_random.as_ref()
    }

    pub(crate) fn on_client_segment(
        &mut self,
        seq: u32,
        payload: &[u8],
        now: Instant,
        store: &KeyLogStore,
    ) -> Step {
        if self.client_stream.push(seq, payload).is_err() {
            return Step::Abandoned(Abandon::Reassembly);
        }
        if let Err(reason) = self.read_client_records() {
            return Step::Abandoned(reason);
        }
        self.progress(now, store)
    }

    pub(crate) fn on_server_segment(
        &mut self,
        seq: u32,
        payload: &[u8],
        now: Instant,
        store: &KeyLogStore,
    ) -> Step {
        if let Some(server) = self.server_stream.as_mut() {
            if server.push(seq, payload).is_err() {
                return Step::Abandoned(Abandon::Reassembly);
            }
            if let Err(reason) = self.read_server_records() {
                return Step::Abandoned(reason);
            }
        }
        self.progress(now, store)
    }

    /// Re-checks a stalled session: a late secret may have arrived, or the deadline passed.
    /// With `force`, a stalled session is abandoned now (end of a capture file).
    pub(crate) fn on_tick(&mut self, now: Instant, store: &KeyLogStore, force: bool) -> Step {
        match self.progress(now, store) {
            Step::Pending if force => Step::Abandoned(self.stall_reason()),
            step => step,
        }
    }

    fn read_client_records(&mut self) -> Result<(), Abandon> {
        // Field borrows so records can be read in place from the stream buffer; only the
        // ones queued for decryption are copied.
        let Self {
            client_stream,
            client_hs,
            client_random,
            client_ccs_seen,
            server_hello,
            encrypted,
            encrypted_bytes,
            limits,
            ..
        } = self;
        let buf = client_stream.ready_bytes();
        let mut pos = 0usize;
        while let Some(record) = next_record(buf, pos).map_err(|_| Abandon::Malformed)? {
            pos = record.end;
            // TLS 1.2 encrypts records after the client's ChangeCipherSpec, with their
            // real type.
            let encrypts_handshake =
                *client_ccs_seen && server_hello.map(|s| s.version) != Some(TlsVersion::Tls13);
            let queue = match record.content_type() {
                CT_HANDSHAKE if client_random.is_none() => {
                    client_hs.extend_from_slice(record.payload);
                    match parse_client_hello(client_hs) {
                        Ok(Some(random)) => {
                            *client_random = Some(random);
                            *client_hs = Vec::new();
                        }
                        Ok(None) => {}
                        Err(_) => return Err(Abandon::Malformed),
                    }
                    false
                }
                CT_CHANGE_CIPHER_SPEC => {
                    *client_ccs_seen = true;
                    false
                }
                CT_HANDSHAKE | CT_ALERT if encrypts_handshake => true,
                // TLS 1.2 ClientKeyExchange / certificate messages before ChangeCipherSpec.
                CT_HANDSHAKE => false,
                CT_APPLICATION_DATA => true,
                _ => return Err(Abandon::Malformed),
            };
            if queue {
                *encrypted_bytes = encrypted_bytes.saturating_add(record.payload.len());
                if *encrypted_bytes > limits.max_client_buffer {
                    return Err(Abandon::Reassembly);
                }
                encrypted.push_back(record.to_owned());
            }
        }
        client_stream.consume(pos);
        Ok(())
    }

    fn read_server_records(&mut self) -> Result<(), Abandon> {
        let Some(server) = self.server_stream.as_mut() else {
            return Ok(());
        };
        let buf = server.ready_bytes();
        let mut pos = 0usize;
        let mut found = None;
        while let Some(record) = next_record(buf, pos).map_err(|_| Abandon::Malformed)? {
            pos = record.end;
            if record.content_type() != CT_HANDSHAKE {
                continue;
            }
            self.server_hs.extend_from_slice(record.payload);
            match parse_server_hello(&self.server_hs) {
                Ok(ServerHelloScan::Found(info)) => {
                    found = Some(info);
                    break;
                }
                Ok(ServerHelloScan::Incomplete) => {}
                Err(_) => return Err(Abandon::Malformed),
            }
            if self.server_hs.len() > self.limits.max_server_buffer {
                return Err(Abandon::Reassembly);
            }
        }
        server.consume(pos);
        if let Some(info) = found {
            let suite = CipherSuite::from_id(info.cipher_suite).ok_or(Abandon::Unsupported)?;
            if suite.version != info.version {
                return Err(Abandon::Unsupported);
            }
            self.server_hello = Some(info);
            self.suite = Some(suite);
            self.server_stream = None;
            self.server_hs = Vec::new();
        }
        Ok(())
    }

    fn progress(&mut self, now: Instant, store: &KeyLogStore) -> Step {
        if matches!(self.phase, Phase::AwaitKeys) {
            match self.try_build_decryptor(store) {
                Ok(true) => {}
                Ok(false) => return self.stall(now),
                Err(reason) => return Step::Abandoned(reason),
            }
        }

        while let Some(record) = self.encrypted.pop_front() {
            self.encrypted_bytes = self.encrypted_bytes.saturating_sub(record.payload.len());
            match self.decrypt_one(&record) {
                Ok(Some(done)) => return done,
                Ok(None) => {}
                Err(reason) => return Step::Abandoned(reason),
            }
        }
        self.stall(now)
    }

    /// Nothing more can be done now; abandon once the deadline passes.
    fn stall(&mut self, now: Instant) -> Step {
        let waiting_for_more = (matches!(self.phase, Phase::AwaitKeys)
            && !self.encrypted.is_empty())
            || self.client_stream.has_gap()
            || self
                .server_stream
                .as_ref()
                .is_some_and(StreamReassembler::has_gap);
        if !waiting_for_more {
            self.deadline = None;
            return Step::Pending;
        }
        let timeout = self.limits.pending_timeout;
        let deadline = *self
            .deadline
            .get_or_insert_with(|| now.checked_add(timeout).unwrap_or(now));
        if now >= deadline {
            return Step::Abandoned(self.stall_reason());
        }
        Step::Pending
    }

    fn stall_reason(&self) -> Abandon {
        if self.client_stream.has_gap()
            || self
                .server_stream
                .as_ref()
                .is_some_and(StreamReassembler::has_gap)
        {
            Abandon::Reassembly
        } else {
            Abandon::NoSecret
        }
    }

    /// `Ok(true)` once a decryptor is ready, `Ok(false)` while waiting for the ServerHello
    /// or the secret.
    fn try_build_decryptor(&mut self, store: &KeyLogStore) -> Result<bool, Abandon> {
        let (Some(random), Some(server), Some(suite)) =
            (self.client_random, self.server_hello, self.suite)
        else {
            return Ok(false);
        };
        if self.encrypted.is_empty() {
            return Ok(false);
        }
        let Some(built) =
            store.with_entry(&random, |entry| self.build_phase(entry, &random, &server, suite))
        else {
            return Ok(false);
        };
        match built {
            Ok(Some(phase)) => {
                self.phase = phase;
                self.deadline = None;
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(reason) => Err(reason),
        }
    }

    fn build_phase(
        &self,
        entry: &KeyEntry,
        client_random: &[u8; 32],
        server: &ServerHelloInfo,
        suite: CipherSuite,
    ) -> Result<Option<Phase>, Abandon> {
        match suite.version {
            TlsVersion::Tls12 => {
                let Some(master) = entry.tls12_master.as_ref() else {
                    return Ok(None);
                };
                let keys =
                    tls12_client_keys(master.as_slice(), client_random, &server.random, suite)
                        .map_err(|_| Abandon::AuthFailed)?;
                let dec = RecordDecryptor::new(suite, &keys).map_err(|_| Abandon::Malformed)?;
                Ok(Some(Phase::Tls12Finished { dec }))
            }
            TlsVersion::Tls13 => {
                let Some(app_secret) = entry.tls13_client_app0.as_ref() else {
                    return Ok(None);
                };
                let app_keys =
                    tls13_traffic_keys(app_secret, suite).map_err(|_| Abandon::AuthFailed)?;
                let app = RecordDecryptor::new(suite, &app_keys).map_err(|_| Abandon::Malformed)?;
                Ok(Some(Phase::Tls13Trial {
                    app: Box::new(app),
                    tried: 0,
                    skipped: Vec::new(),
                    hs_secret: entry.tls13_client_hs.clone(),
                }))
            }
        }
    }

    /// The app-key trial ran out: decrypt from the start with the handshake key instead,
    /// replaying the records the trial skipped before the ones still queued.
    fn replay_with_handshake_key(
        &mut self,
        hs_secret: &[u8],
        skipped: Vec<RawRecord>,
        app: RecordDecryptor,
    ) -> Result<Phase, Abandon> {
        let suite = self.suite.ok_or(Abandon::Malformed)?;
        let hs_keys = tls13_traffic_keys(hs_secret, suite).map_err(|_| Abandon::AuthFailed)?;
        let hs = RecordDecryptor::new(suite, &hs_keys).map_err(|_| Abandon::Malformed)?;
        for record in skipped.into_iter().rev() {
            self.encrypted_bytes = self.encrypted_bytes.saturating_add(record.payload.len());
            self.encrypted.push_front(record);
        }
        Ok(Phase::Tls13Handshake { hs, app })
    }

    /// Decrypts one queued record. `Ok(Some(step))` ends the session.
    fn decrypt_one(&mut self, record: &RawRecord) -> Result<Option<Step>, Abandon> {
        let phase = std::mem::replace(&mut self.phase, Phase::AwaitKeys);
        let (next, plaintext) = match phase {
            Phase::AwaitKeys => return Err(Abandon::Malformed),
            Phase::Tls13Handshake { mut hs, app } => {
                let (ct, plain) = hs.open(record).map_err(record_abandon)?;
                if ct == CT_HANDSHAKE && contains_finished(&plain) {
                    (Phase::App { dec: app }, None)
                } else {
                    (Phase::Tls13Handshake { hs, app }, None)
                }
            }
            Phase::Tls13Trial { mut app, tried, mut skipped, hs_secret } => {
                match app.open(record) {
                    Ok((ct, plain)) => (Phase::App { dec: *app }, Some((ct, plain))),
                    Err(RecordError::Auth) => {
                        let tried = tried.saturating_add(1);
                        if hs_secret.is_some() {
                            skipped.push(record.clone());
                        }
                        if tried < TLS13_TRIAL_RECORDS {
                            (Phase::Tls13Trial { app, tried, skipped, hs_secret }, None)
                        } else {
                            let hs_secret = hs_secret.ok_or(Abandon::AuthFailed)?;
                            (self.replay_with_handshake_key(&hs_secret, skipped, *app)?, None)
                        }
                    }
                    Err(e) => return Err(record_abandon(e)),
                }
            }
            Phase::Tls12Finished { mut dec } => {
                let (ct, _finished) = dec.open(record).map_err(record_abandon)?;
                if ct != CT_HANDSHAKE {
                    return Err(Abandon::Malformed);
                }
                (Phase::App { dec }, None)
            }
            Phase::App { mut dec } => {
                let (ct, plain) = dec.open(record).map_err(record_abandon)?;
                (Phase::App { dec }, Some((ct, plain)))
            }
        };
        self.phase = next;

        let Some((content_type, plain)) = plaintext else {
            return Ok(None);
        };
        match content_type {
            CT_APPLICATION_DATA => {}
            // Post-handshake messages (TLS 1.3 NewSessionTicket/KeyUpdate from the client side
            // are rare); nothing to fingerprint.
            CT_HANDSHAKE => return Ok(None),
            CT_ALERT => return Err(Abandon::NotHttp2),
            _ => return Err(Abandon::Malformed),
        }
        let suite = self.suite.ok_or(Abandon::Malformed)?;
        match self.akamai.push(&plain) {
            Ok(Some(fingerprint)) => {
                Ok(Some(Step::Done { fingerprint, version: suite.version, cipher_suite: suite.id }))
            }
            Ok(None) => Ok(None),
            Err(AccumulatorError::NotHttp2) => Err(Abandon::NotHttp2),
            Err(AccumulatorError::TooLarge) => Err(Abandon::Reassembly),
            Err(AccumulatorError::Malformed) => Err(Abandon::Malformed),
        }
    }
}

fn record_abandon(e: RecordError) -> Abandon {
    match e {
        RecordError::Auth => Abandon::AuthFailed,
        RecordError::Malformed => Abandon::Malformed,
    }
}

/// Whether decrypted TLS 1.3 handshake bytes contain a Finished message.
fn contains_finished(plain: &[u8]) -> bool {
    let mut pos = 0usize;
    while let Some(header) = plain.get(pos..pos.saturating_add(4)) {
        if header[0] == HS_FINISHED {
            return true;
        }
        let len =
            usize::from(header[1]) << 16 | usize::from(header[2]) << 8 | usize::from(header[3]);
        pos = pos.saturating_add(4).saturating_add(len);
    }
    false
}
