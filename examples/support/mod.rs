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

/// Shared CLI commands for examples with live (single/parallel) + pcap modes.
/// Used by cli-tcp and cli-http. cli-tls has extra parallel fields; cli has no LiveMode.
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

/// `name`, or `name variant` when the signature carries a variant.
#[allow(dead_code)]
pub fn with_variant(name: &str, variant: Option<&str>) -> String {
    match variant {
        Some(variant) if !variant.is_empty() => format!("{name} {variant}"),
        _ => name.to_string(),
    }
}

/// One event per line: the observed signature, then the matcher result.
/// Colored when stdout is a terminal.
#[allow(clippy::too_many_arguments)]
pub fn print_event(
    proto: &str,
    proto_color: &str,
    label: &str,
    from: &str,
    to: &str,
    signature: &str,
    matched: &str,
    match_color: &str,
    note: Option<&str>,
) {
    let mut line = format!(
        "{}  {}  {} → {}  {}  {}",
        paint(&fit(proto, 4), proto_color),
        fit(label, 6),
        fit(from, 22),
        fit(to, 28),
        pad_min(signature, 56),
        paint(matched, match_color),
    );
    if let Some(note) = note {
        line.push_str("  ");
        line.push_str(&paint(note, "2"));
    }
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{line}");
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
