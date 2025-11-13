use clap::{Parser, Subcommand};
use huginn_net_db::Database;
use huginn_net_http::{HttpAnalysisResult, HuginnNetHttp};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
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

    #[arg(short = 'l', long = "log-file")]
    log_file: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Commands {
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

    info!("Starting HTTP-only capture example");

    let (sender, receiver): (Sender<HttpAnalysisResult>, Receiver<HttpAnalysisResult>) = channel();

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
        let db = match Database::load_default() {
            Ok(db) => db,
            Err(e) => {
                error!("Failed to load default database: {e}");
                return;
            }
        };
        debug!("Loaded database: {:?}", db);

        let db_option = Some(Arc::new(db));

        match args.command {
            Commands::Single { interface } => {
                info!("Initializing HTTP analyzer in sequential mode");
                let mut analyzer = match HuginnNetHttp::new(db_option, 1000) {
                    Ok(analyzer) => analyzer,
                    Err(e) => {
                        error!("Failed to create HuginnNetHttp analyzer: {e}");
                        return;
                    }
                };

                info!("Starting HTTP live capture on interface: {interface}");
                if let Err(e) =
                    analyzer.analyze_network(&interface, sender, Some(thread_cancel_signal))
                {
                    error!("HTTP analysis failed: {e}");
                }
            }
            Commands::Parallel { interface, workers, queue_size } => {
                info!(
                    "Initializing HTTP analyzer with {workers} worker threads (flow-based routing)"
                );
                let mut analyzer =
                    match HuginnNetHttp::with_config(db_option, 1000, workers, queue_size) {
                        Ok(analyzer) => analyzer,
                        Err(e) => {
                            error!("Failed to create HuginnNetHttp analyzer: {e}");
                            return;
                        }
                    };

                if let Err(e) = analyzer.init_pool(sender.clone()) {
                    error!("Failed to initialize worker pool: {e}");
                    return;
                }

                info!("Starting HTTP live capture on interface: {interface}");
                if let Err(e) =
                    analyzer.analyze_network(&interface, sender, Some(thread_cancel_signal))
                {
                    error!("HTTP analysis failed: {e}");
                }
            }
        }
    });

    for output in receiver {
        if cancel_signal.load(Ordering::Relaxed) {
            info!("Shutdown signal received, stopping result processing");
            break;
        }

        if let Some(http_request) = output.http_request {
            info!("{http_request}");
        }
        if let Some(http_response) = output.http_response {
            info!("{http_response}");
        }
    }

    info!("Analysis shutdown completed");
}
