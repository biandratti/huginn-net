use clap::{Parser, Subcommand};
use huginn_net_tls::{HuginnNetTls, TlsClientOutput};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
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
    #[arg(short = 'l', long = "log-file", global = true)]
    log_file: Option<String>,

    /// Enable parallel processing with N workers (default: 1 = sequential)
    #[arg(
        short = 'p',
        long = "parallel-workers",
        default_value = "1",
        global = true
    )]
    parallel_workers: usize,

    /// Queue size for parallel processing
    #[arg(short = 'q', long = "queue-size", default_value = "100", global = true)]
    queue_size: usize,
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
    let monitor_cancel_signal = cancel_signal.clone();

    let parallel_workers = args.parallel_workers;

    let mut analyzer = if parallel_workers > 1 {
        let queue_size = args.queue_size;
        info!("Using parallel mode with {parallel_workers} workers, queue_size={queue_size}");
        HuginnNetTls::with_config(parallel_workers, queue_size)
    } else {
        info!("Using sequential mode");
        HuginnNetTls::new()
    };

    // Initialize pool if parallel mode (before moving analyzer to thread)
    if parallel_workers > 1 {
        if let Err(e) = analyzer.init_pool(sender.clone()) {
            error!("Failed to initialize worker pool: {e}");
            return;
        }
    }

    // Get pool reference before moving analyzer
    let worker_pool_monitor = analyzer.worker_pool();
    let worker_pool_shutdown = worker_pool_monitor.clone();

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

    // Start analysis thread
    thread::spawn(move || {
        let interface = match &args.command {
            Commands::Live { interface } => interface.clone(),
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
            error!("TLS analysis failed: {e}");
        }
    });

    // Spawn monitoring thread if we have a pool
    if let Some(pool) = worker_pool_monitor.clone() {
        thread::spawn(move || {
            let mut counter: u8 = 0;
            loop {
                // Check cancel signal frequently (every 100ms)
                thread::sleep(Duration::from_millis(100));

                if monitor_cancel_signal.load(Ordering::Relaxed) {
                    break;
                }

                counter = counter.saturating_add(1);
                // Log stats every 5 seconds (50 * 100ms)
                if counter >= 50 {
                    counter = 0;
                    let stats = pool.stats();
                    info!(
                        "TLS stats - dispatched: {}, dropped: {}",
                        stats.total_dispatched, stats.total_dropped
                    );
                }
            }
        });
    }

    for output in receiver {
        if cancel_signal.load(Ordering::Relaxed) {
            info!("Shutdown signal received, stopping result processing");
            break;
        }

        info!("{output}");

        // Log worker stats if parallel mode
        if let Some(ref pool) = worker_pool_monitor {
            let stats = pool.stats();
            for worker in &stats.workers {
                info!(
                    "  Worker {}: queue_size={}, dropped={}",
                    worker.id, worker.queue_size, worker.dropped
                );
            }
        }
    }

    info!("Analysis shutdown completed");
}
