use clap::{Parser, Subcommand};
use huginn_net_tls::{HuginnNetTls, TlsClientOutput};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::thread;
use tracing::{error, info};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,

    /// Log file path
    #[arg(short = 'l', long = "log-file")]
    log_file: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Live {
        /// Network interface name
        #[arg(short = 'i', long)]
        interface: String,
    },
}

fn initialize_logging(log_file: Option<String>) {
    let console_writer = std::io::stdout.with_max_level(tracing::Level::INFO);

    let file_appender = if let Some(log_file) = log_file {
        RollingFileAppender::new(Rotation::NEVER, ".", log_file)
            .with_max_level(tracing::Level::INFO)
    } else {
        RollingFileAppender::new(Rotation::NEVER, ".", "tls-capture.log")
            .with_max_level(tracing::Level::INFO)
    };

    let writer = console_writer.and(file_appender);

    let subscriber = fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(writer)
        .finish();

    if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
        eprintln!("Failed to set subscriber: {e}");
        std::process::exit(1);
    }
}

fn main() {
    let args = Args::parse();
    initialize_logging(args.log_file.clone());

    info!("Starting TLS-only capture example");

    let (sender, receiver): (Sender<TlsClientOutput>, Receiver<TlsClientOutput>) = mpsc::channel();

    let cancel_signal = Arc::new(AtomicBool::new(false));
    let ctrl_c_signal = cancel_signal.clone();
    let thread_cancel_signal = cancel_signal.clone();

    if let Err(e) = ctrlc::set_handler(move || {
        info!("Received signal, initiating graceful shutdown...");
        ctrl_c_signal.store(true, Ordering::Relaxed);
    }) {
        error!("Error setting signal handler: {e}");
        return;
    }

    thread::spawn(move || {
        let mut analyzer = HuginnNetTls::new();

        let result = match args.command {
            Commands::Live { interface } => {
                info!("Starting TLS live capture on interface: {}", interface);
                analyzer.analyze_network(&interface, sender, Some(thread_cancel_signal))
            }
        };

        if let Err(e) = result {
            error!("TLS analysis failed: {e}");
        }
    });

    for output in receiver {
        if cancel_signal.load(Ordering::Relaxed) {
            info!("Shutdown signal received, stopping result processing");
            break;
        }

        info!("{}", output);
    }

    info!("Analysis shutdown completed");
}
