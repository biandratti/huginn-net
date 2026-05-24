use clap::{Parser, Subcommand, ValueEnum};
use huginn_net_tls::{FilterConfig, HuginnNetTls, IpFilter, PortFilter, TlsClientOutput};
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

#[derive(ValueEnum, Debug, Clone, Default)]
enum OutputFormat {
    #[default]
    Human,
    Json,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,

    #[command(flatten)]
    filter: FilterOptions,

    #[arg(short = 'l', long = "log-file")]
    log_file: Option<String>,

    #[arg(long, value_enum, default_value = "human")]
    format: OutputFormat,
}

#[derive(Parser, Debug)]
struct FilterOptions {
    #[arg(short = 'p', long = "port")]
    port: Option<u16>,

    #[arg(short = 'I', long = "ip")]
    ip: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Commands {
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
enum LiveMode {
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

        #[arg(short = 'b', long = "batch-size", default_value = "32")]
        batch_size: usize,

        #[arg(short = 't', long = "timeout-ms", default_value = "10")]
        timeout_ms: u64,
    },
}

fn initialize_logging(log_file: Option<String>, use_stderr: bool) {
    let file_appender = if let Some(log_file) = log_file {
        RollingFileAppender::new(Rotation::NEVER, ".", log_file)
            .with_max_level(tracing::Level::INFO)
    } else {
        RollingFileAppender::new(Rotation::NEVER, ".", "tls-capture.log")
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

fn build_filter(port: Option<u16>, ip: Option<String>) -> Option<FilterConfig> {
    let has_port = port.is_some();
    let has_ip = ip.is_some();

    if !has_port && !has_ip {
        return None;
    }

    let mut filter = FilterConfig::new();

    if let Some(dst_port) = port {
        filter = filter.with_port_filter(PortFilter::new().destination(dst_port));
        info!("Filter: destination port {}", dst_port);
    }

    if let Some(ip_str) = ip {
        match IpFilter::new().allow(&ip_str) {
            Ok(ip_filter) => {
                filter = filter.with_ip_filter(ip_filter);
                info!("Filter: IP address {}", ip_str);
            }
            Err(e) => {
                error!("Invalid IP address '{}': {}", ip_str, e);
                return None;
            }
        }
    }

    Some(filter)
}

fn main() {
    let args = Args::parse();
    let format = args.format;

    initialize_logging(args.log_file, matches!(format, OutputFormat::Json));

    #[cfg(not(feature = "json"))]
    if matches!(format, OutputFormat::Json) {
        error!("error: --format json requires the `json` feature");
        info!("hint:  cargo run --example capture-tls --features full,json -- --format json ...");
        std::process::exit(1);
    }

    info!("Starting TLS-only capture example");

    let mut packet_count: u64 = 0;
    const LOG_STATS_EVERY: u64 = 100;

    let (sender, receiver): (Sender<TlsClientOutput>, Receiver<TlsClientOutput>) = mpsc::channel();

    let cancel_signal = Arc::new(AtomicBool::new(false));
    let ctrl_c_signal = cancel_signal.clone();
    let thread_cancel_signal = cancel_signal.clone();

    let mut analyzer = match &args.command {
        Commands::Live { mode } => match mode {
            LiveMode::Single { .. } => {
                info!("Using sequential mode");
                let mut analyzer = HuginnNetTls::new(10000);
                if let Some(filter_config) = build_filter(args.filter.port, args.filter.ip.clone())
                {
                    analyzer = analyzer.with_filter(filter_config);
                    info!("Packet filtering enabled");
                }
                analyzer
            }
            LiveMode::Parallel { workers, queue_size, batch_size, timeout_ms, .. } => {
                info!("Using parallel mode: workers={workers}, queue_size={queue_size}, batch_size={batch_size}, timeout_ms={timeout_ms}");
                let mut analyzer = HuginnNetTls::new(10000).with_parallel(
                    *workers,
                    *queue_size,
                    *batch_size,
                    *timeout_ms,
                );
                if let Some(filter_config) = build_filter(args.filter.port, args.filter.ip.clone())
                {
                    analyzer = analyzer.with_filter(filter_config);
                    info!("Packet filtering enabled");
                }
                analyzer
            }
        },
        Commands::Pcap { .. } => {
            info!("Using sequential mode for PCAP");
            let mut analyzer = HuginnNetTls::new(10000);
            if let Some(filter_config) = build_filter(args.filter.port, args.filter.ip.clone()) {
                analyzer = analyzer.with_filter(filter_config);
                info!("Packet filtering enabled");
            }
            analyzer
        }
    };

    if matches!(&args.command, Commands::Live { mode: LiveMode::Parallel { .. } }) {
        if let Err(e) = analyzer.init_pool(sender.clone()) {
            error!("Failed to initialize worker pool: {e}");
            return;
        }
    }

    let worker_pool_monitor = analyzer.worker_pool();
    let worker_pool_shutdown = worker_pool_monitor.clone();

    if let Err(e) = ctrlc::set_handler(move || {
        info!("Received signal, initiating graceful shutdown...");
        ctrl_c_signal.store(true, Ordering::Relaxed);

        if let Some(ref pool) = worker_pool_shutdown {
            pool.shutdown();
        }
    }) {
        error!("Error setting signal handler: {e}");
        return;
    }

    if let Commands::Pcap { file } = &args.command {
        info!("Processing PCAP file: {}", file);
        match analyzer.analyze_pcap(file, sender, None) {
            Ok(_) => {
                info!("PCAP analysis completed successfully");
            }
            Err(e) => {
                error!("PCAP analysis failed: {e}");
                return;
            }
        }
    } else if let Commands::Live { mode } = &args.command {
        let analyzer_shared = Arc::new(std::sync::Mutex::new(analyzer));

        let interface = match mode {
            LiveMode::Single { interface, .. } => interface.clone(),
            LiveMode::Parallel { interface, .. } => interface.clone(),
        };

        thread::spawn(move || {
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
    }

    for output in receiver {
        if cancel_signal.load(Ordering::Relaxed) {
            info!("Shutdown signal received, stopping result processing");
            break;
        }

        match format {
            OutputFormat::Human => info!("{output}"),
            OutputFormat::Json =>
            {
                #[cfg(feature = "json")]
                match serde_json::to_string(&output) {
                    Ok(json) => println!("{json}"),
                    Err(e) => error!("Failed to serialize output: {e}"),
                }
            }
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
