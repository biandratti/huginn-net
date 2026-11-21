#![allow(dead_code)]
// Shared helpers compiled as a module by each example binary.
#![allow(clippy::exit, clippy::print_stderr, unreachable_pub)]

use std::io::{IsTerminal, Write};
use std::net::IpAddr;

use clap::Subcommand;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::fmt::writer::MakeWriterExt;

#[derive(clap::Args, Debug)]
pub struct FilterOptions {
    #[arg(short = 'p', long = "port")]
    pub port: Option<u16>,

    #[arg(short = 'I', long = "ip")]
    pub ip: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Live {
        #[command(subcommand)]
        mode: LiveMode,
    },
    Pcap {
        #[arg(short = 'f', long = "file")]
        file: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum LiveMode {
    Single {
        #[arg(short = 'i', long)]
        interface: String,
    },
    Parallel {
        #[arg(short = 'i', long)]
        interface: String,

        #[arg(short = 'w', long = "workers")]
        workers: usize,

        #[arg(short = 'q', long = "queue-size", default_value = "100")]
        queue_size: usize,
    },
}

pub fn initialize_logging(log_file: Option<String>) {
    let file_appender = if let Some(log_file) = log_file {
        RollingFileAppender::new(Rotation::NEVER, ".", log_file)
            .with_max_level(tracing::Level::INFO)
    } else {
        RollingFileAppender::new(Rotation::NEVER, ".", "default.log")
            .with_max_level(tracing::Level::INFO)
    };

    let writer = std::io::stderr
        .with_max_level(tracing::Level::INFO)
        .and(file_appender);
    let result = tracing::subscriber::set_global_default(
        fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .with_writer(writer)
            .finish(),
    );

    if let Err(e) = result {
        eprintln!("Failed to set subscriber: {e}");
        std::process::exit(1);
    }
}

pub fn endpoint(ip: &IpAddr, port: u16) -> String {
    format!("{ip}:{port}")
}

const KIND_WIDTH: usize = 13;

#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    Syn,
    SynAck,
    Mtu,
    UptimeClient,
    UptimeServer,
    HttpRequest,
    HttpResponse,
    Tls,
    TlsS1,
}

impl Kind {
    fn protocol(&self) -> Protocol {
        match self {
            Self::Syn | Self::SynAck | Self::Mtu | Self::UptimeClient | Self::UptimeServer => {
                Protocol::Tcp
            }
            Self::HttpRequest | Self::HttpResponse => Protocol::Http,
            Self::Tls | Self::TlsS1 => Protocol::Tls,
        }
    }

    fn label(&self) -> &str {
        match self {
            Self::Syn => "SYN",
            Self::SynAck => "SYNACK",
            Self::Mtu => "MTU",
            Self::UptimeClient => "UPTIME-CLIENT",
            Self::UptimeServer => "UPTIME-SERVER",
            Self::HttpRequest => "REQUEST",
            Self::HttpResponse => "RESPONSE",
            Self::Tls => "JA4",
            Self::TlsS1 => "S1",
        }
    }

    /// ANSI color of the record label, so each kind is recognizable at a glance.
    fn color(&self) -> &'static str {
        match self {
            Self::Syn => "1;33",
            Self::SynAck => "1;93",
            Self::Mtu => "1;31",
            Self::UptimeClient => "1;96",
            Self::UptimeServer => "1;94",
            Self::HttpRequest => "1;92",
            Self::HttpResponse => "1;91",
            Self::Tls => "1;95",
            Self::TlsS1 => "1;37",
        }
    }
}

pub fn os_match(os: Option<(&str, Option<&str>)>) -> Match {
    os.map_or(Match::Miss, |(name, variant)| Match::hit(named(name, variant)))
}

/// Matcher column for a browser or web server that may be absent.
/// An empty name falls back to the family.
pub fn product(item: Option<(&str, Option<&str>, Option<&str>)>) -> Match {
    item.map_or(Match::Miss, |(name, family, variant)| {
        let base = if name.is_empty() {
            family.unwrap_or("???")
        } else {
            name
        };
        Match::hit(named(base, variant))
    })
}

/// Matcher column for an optional link name (MTU).
pub fn link(name: Option<&str>) -> Match {
    name.map_or(Match::Miss, |name| Match::hit(name.to_string()))
}

fn named(name: &str, variant: Option<&str>) -> String {
    match variant {
        Some(variant) if !variant.is_empty() => format!("{name} {variant}"),
        _ => name.to_string(),
    }
}

#[derive(Clone, Copy)]
enum Protocol {
    Tcp,
    Http,
    Tls,
}

impl Protocol {
    fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Http => "HTTP",
            Self::Tls => "TLS",
        }
    }

    fn color(self) -> &'static str {
        match self {
            Self::Tcp => "1;36",
            Self::Http => "1;34",
            Self::Tls => "1;35",
        }
    }
}

/// Result shown after the observed signature.
pub enum Match {
    /// A database label. Painted when stdout is a terminal.
    Hit(String),
    /// Looked up, nothing matched (`???`).
    Miss,
    /// This record has no matcher (`—`).
    None,
}

impl Match {
    pub fn hit(text: impl Into<String>) -> Self {
        Self::Hit(text.into())
    }

    fn text(&self) -> &str {
        match self {
            Self::Hit(text) => text,
            Self::Miss => "???",
            Self::None => "—",
        }
    }

    fn color(&self) -> &'static str {
        match self {
            Self::Hit(_) => "1;32",
            Self::Miss | Self::None => "2",
        }
    }
}

/// One analysis record. The layout (columns, widths, colors) lives here.
pub struct Event {
    kind: Kind,
    from: String,
    to: String,
    signature: String,
    matched: Match,
    note: Option<String>,
}

impl Event {
    pub fn new(kind: Kind) -> Self {
        Self {
            kind,
            from: String::new(),
            to: String::new(),
            signature: String::new(),
            matched: Match::None,
            note: None,
        }
    }

    pub fn flow(mut self, from: impl AsRef<str>, to: impl AsRef<str>) -> Self {
        self.from = from.as_ref().to_string();
        self.to = to.as_ref().to_string();
        self
    }

    pub fn between(
        self,
        source_ip: &IpAddr,
        source_port: u16,
        dest_ip: &IpAddr,
        dest_port: u16,
    ) -> Self {
        self.flow(endpoint(source_ip, source_port), endpoint(dest_ip, dest_port))
    }

    pub fn signature(mut self, signature: impl AsRef<str>) -> Self {
        self.signature = signature.as_ref().to_string();
        self
    }

    pub fn matched(mut self, matched: Match) -> Self {
        self.matched = matched;
        self
    }

    pub fn note(mut self, note: impl AsRef<str>) -> Self {
        self.note = Some(note.as_ref().to_string());
        self
    }

    pub fn note_opt(self, note: Option<&str>) -> Self {
        match note {
            Some(note) => self.note(note),
            None => self,
        }
    }

    pub fn emit(self) {
        let protocol = self.kind.protocol();
        let mut line = format!(
            "{}  {}  {} → {}  {}  {}",
            paint(&fit(protocol.as_str(), 4), protocol.color()),
            paint(&fit(self.kind.label(), KIND_WIDTH), self.kind.color()),
            fit(&self.from, 22),
            fit(&self.to, 28),
            pad_min(&self.signature, 56),
            paint(self.matched.text(), self.matched.color()),
        );
        if let Some(note) = &self.note {
            line.push_str("  ");
            line.push_str(&paint(note, "2"));
        }
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{line}");
    }
}

fn paint(text: &str, code: &str) -> String {
    if std::io::stdout().is_terminal() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

fn pad_min(value: &str, width: usize) -> String {
    let mut padded = value.to_string();
    padded.extend(std::iter::repeat_n(' ', width.saturating_sub(value.chars().count())));
    padded
}

fn fit(value: &str, width: usize) -> String {
    let count = value.chars().count();
    if count > width {
        let keep = width.saturating_sub(1);
        let mut fitted: String = value.chars().take(keep).collect();
        fitted.push('…');
        fitted
    } else {
        let mut fitted = value.to_string();
        fitted.extend(std::iter::repeat_n(' ', width.saturating_sub(count)));
        fitted
    }
}
