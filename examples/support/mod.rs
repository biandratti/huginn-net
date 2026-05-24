use clap::{Subcommand, ValueEnum};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::EnvFilter;

#[derive(ValueEnum, Debug, Clone, Default)]
pub enum OutputFormat {
    #[default]
    Human,
    Json,
}

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

pub fn initialize_logging(log_file: Option<String>, use_stderr: bool) {
    let file_appender = if let Some(log_file) = log_file {
        RollingFileAppender::new(Rotation::NEVER, ".", log_file)
            .with_max_level(tracing::Level::INFO)
    } else {
        RollingFileAppender::new(Rotation::NEVER, ".", "default.log")
            .with_max_level(tracing::Level::INFO)
    };

    let result = if use_stderr {
        let writer = std::io::stderr
            .with_max_level(tracing::Level::INFO)
            .and(file_appender);
        tracing::subscriber::set_global_default(
            fmt()
                .with_env_filter(EnvFilter::from_default_env())
                .with_writer(writer)
                .finish(),
        )
    } else {
        let writer = std::io::stdout
            .with_max_level(tracing::Level::INFO)
            .and(file_appender);
        tracing::subscriber::set_global_default(
            fmt()
                .with_env_filter(EnvFilter::from_default_env())
                .with_writer(writer)
                .finish(),
        )
    };

    if let Err(e) = result {
        eprintln!("Failed to set subscriber: {e}");
        std::process::exit(1);
    }
}
