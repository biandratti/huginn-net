use clap::{Parser, Subcommand};
use huginn_net::output::FingerprintResult;
use huginn_net::Database;
use huginn_net::HuginnNet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::thread;
use tracing::{debug, error, info};
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
    Pcap {
        /// Path to PCAP file
        #[arg(short = 'f', long)]
        file: String,
    },
}

fn initialize_logging(log_file: Option<String>) {
    let console_writer = std::io::stdout.with_max_level(tracing::Level::INFO);

    let file_appender = if let Some(log_file) = log_file {
        RollingFileAppender::new(Rotation::NEVER, ".", log_file)
            .with_max_level(tracing::Level::INFO)
    } else {
        RollingFileAppender::new(Rotation::NEVER, ".", "default.log")
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
    initialize_logging(args.log_file);

    let (sender, receiver): (Sender<FingerprintResult>, Receiver<FingerprintResult>) =
        mpsc::channel();

    let cancel_signal = Arc::new(AtomicBool::new(false));
    let cancel_clone = cancel_signal.clone();

    let ctrl_c_signal = cancel_signal.clone();
    if let Err(e) = ctrlc::set_handler(move || {
        info!("Received signal, initiating graceful shutdown...");
        ctrl_c_signal.store(true, Ordering::Relaxed);
    }) {
        error!("Error setting signal handler: {e}");
        return;
    }

    thread::spawn(move || {
        let db = match Database::load_default() {
            Ok(db) => db,
            Err(e) => {
                error!("Failed to load default database: {}", e);
                return;
            }
        };
        debug!("Loaded database: {:?}", db);

        let mut analyzer = match HuginnNet::new(Some(&db), 100, None) {
            Ok(analyzer) => analyzer,
            Err(e) => {
                error!("Failed to create HuginnNet analyzer: {}", e);
                return;
            }
        };

        let result = match args.command {
            Commands::Live { interface } => {
                info!("Starting live capture on interface: {}", interface);
                analyzer.analyze_network(&interface, sender, Some(cancel_clone))
            }
            Commands::Pcap { file } => {
                info!("Analyzing PCAP file: {}", file);
                analyzer.analyze_pcap(&file, sender, Some(cancel_clone))
            }
        };

        if let Err(e) = result {
            eprintln!("Analysis failed: {e}");
        }
    });

    for output in receiver {
        if cancel_signal.load(Ordering::Relaxed) {
            info!("Shutdown signal received, stopping result processing");
            break;
        }

        if let Some(syn) = output.syn {
            info!("{}", syn);
        }
        if let Some(syn_ack) = output.syn_ack {
            info!("{}", syn_ack);
        }
        if let Some(mtu) = output.mtu {
            info!("{}", mtu);
        }
        if let Some(uptime) = output.uptime {
            info!("{}", uptime);
        }
        if let Some(http_request) = output.http_request {
            info!("{}", http_request);
        }
        if let Some(http_response) = output.http_response {
            info!("{}", http_response);
        }
        if let Some(tls_client) = output.tls_client {
            info!("{}", tls_client);
        }
    }

    info!("Analysis shutdown completed");
}
