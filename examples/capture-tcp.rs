use clap::{Parser, Subcommand};
use huginn_net_db::Database;
use huginn_net_tcp::{HuginnNetTcp, TcpAnalysisResult};
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
    /// Capture from live network interface in sequential mode
    Single {
        /// Network interface name
        #[arg(short = 'i', long)]
        interface: String,
    },
    /// Capture from live network interface in parallel mode
    Parallel {
        /// Network interface name
        #[arg(short = 'i', long)]
        interface: String,

        /// Number of worker threads
        #[arg(short = 'w', long = "workers")]
        workers: usize,

        /// Queue size per worker
        #[arg(short = 'q', long = "queue-size", default_value = "100")]
        queue_size: usize,
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

    let (sender, receiver): (Sender<TcpAnalysisResult>, Receiver<TcpAnalysisResult>) =
        mpsc::channel();

    let db = match Database::load_default() {
        Ok(db) => Arc::new(db),
        Err(e) => {
            error!("Failed to load default database: {e}");
            return;
        }
    };
    debug!("Loaded p0f database successfully");

    let mut analyzer = match &args.command {
        Commands::Single { .. } => {
            info!("Using sequential mode");
            match HuginnNetTcp::new(Some(db), 1000) {
                Ok(analyzer) => analyzer,
                Err(e) => {
                    error!("Failed to create HuginnNetTcp analyzer: {e}");
                    return;
                }
            }
        }
        Commands::Parallel { workers, queue_size, .. } => {
            info!("Using parallel mode with {workers} workers, queue_size={queue_size}");
            match HuginnNetTcp::with_config(Some(db), 1000, *workers, *queue_size) {
                Ok(analyzer) => analyzer,
                Err(e) => {
                    error!("Failed to create HuginnNetTcp analyzer: {e}");
                    return;
                }
            }
        }
    };

    // Initialize pool if parallel mode
    if matches!(&args.command, Commands::Parallel { .. }) {
        if let Err(e) = analyzer.init_pool(sender.clone()) {
            error!("Failed to initialize worker pool: {e}");
            return;
        }
    }

    // Get pool reference before moving analyzer
    let worker_pool_monitor = analyzer.worker_pool();
    let worker_pool_shutdown = worker_pool_monitor.clone();

    let cancel_signal = Arc::new(AtomicBool::new(false));
    let ctrl_c_signal = cancel_signal.clone();
    let thread_cancel_signal = cancel_signal.clone();

    // Setup Ctrl-C handler with pool shutdown
    if let Err(e) = ctrlc::set_handler(move || {
        info!("Received signal, initiating graceful shutdown...");
        ctrl_c_signal.store(true, Ordering::Relaxed);

        // Shutdown worker pool if it exists
        if let Some(ref pool) = worker_pool_shutdown {
            pool.shutdown();
        }
    }) {
        error!("Error setting signal handler: {e}");
        return;
    }

    let analyzer_shared = Arc::new(std::sync::Mutex::new(analyzer));

    thread::spawn(move || {
        let interface = match &args.command {
            Commands::Single { interface } => interface.clone(),
            Commands::Parallel { interface, .. } => interface.clone(),
        };

        let result = {
            let mut analyzer = match analyzer_shared.lock() {
                Ok(a) => a,
                Err(_) => {
                    error!("Failed to lock analyzer");
                    return;
                }
            };
            analyzer.analyze_network(&interface, sender, Some(thread_cancel_signal))
        };

        if let Err(e) = result {
            error!("TCP analysis failed: {e}");
        }
    });

    const LOG_STATS_EVERY: u64 = 1000;
    let mut packet_count: u64 = 0;

    for output in receiver {
        if cancel_signal.load(Ordering::Relaxed) {
            info!("Shutdown signal received, stopping result processing");
            break;
        }

        if let Some(syn) = output.syn {
            info!("{syn}");
        }
        if let Some(syn_ack) = output.syn_ack {
            info!("{syn_ack}");
        }
        if let Some(mtu) = output.mtu {
            info!("{mtu}");
        }
        if let Some(client_uptime) = output.client_uptime {
            info!("{client_uptime}");
        }
        if let Some(server_uptime) = output.server_uptime {
            info!("{server_uptime}");
        }

        if let Some(ref pool) = worker_pool_monitor {
            packet_count = packet_count.saturating_add(1);

            if packet_count % LOG_STATS_EVERY == 0 {
                let stats = pool.stats();
                info!("{stats}");
            }
        }
    }

    info!("Analysis shutdown completed");
}
