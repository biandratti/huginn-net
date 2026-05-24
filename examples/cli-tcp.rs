#[path = "support/mod.rs"]
mod support;
use support::{initialize_logging, Commands, FilterOptions, LiveMode, OutputFormat};

use clap::Parser;
use huginn_net_db::{Database, SharedTcpSignatureMatcher};
use huginn_net_tcp::matcher_api::TcpMatcher;
use huginn_net_tcp::{FilterConfig, HuginnNetTcp, IpFilter, PortFilter, TcpAnalysisResult};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::thread;
use tracing::{debug, error, info};

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

fn build_filter(filter_options: &FilterOptions) -> Option<FilterConfig> {
    let has_port = filter_options.port.is_some();
    let has_ip = filter_options.ip.is_some();

    if !has_port && !has_ip {
        return None;
    }

    let mut filter = FilterConfig::new();

    if let Some(dst_port) = filter_options.port {
        filter = filter.with_port_filter(PortFilter::new().destination(dst_port));
        info!("Filter: destination port {}", dst_port);
    }

    if let Some(ip_str) = &filter_options.ip {
        match IpFilter::new().allow(ip_str) {
            Ok(ip_filter) => {
                filter = filter.with_ip_filter(ip_filter);
                info!("Filter: IP address {}", ip_str);
            }
            Err(e) => {
                error!("Invalid IP address '{}': {}", ip_str, e);
                std::process::exit(1);
            }
        }
    }

    Some(filter)
}

fn main() {
    let args = Args::parse();

    initialize_logging(args.log_file, matches!(args.format, OutputFormat::Json));

    #[cfg(not(feature = "json"))]
    if matches!(args.format, OutputFormat::Json) {
        error!("error: --format json requires the `json` feature");
        info!("hint:  cargo run --example cli-tcp --features full,json -- --format json ...");
        std::process::exit(1);
    }

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
    let matcher: Arc<dyn TcpMatcher + Send + Sync> =
        Arc::new(SharedTcpSignatureMatcher::from_database(&db));

    let filter_config = build_filter(&args.filter);

    let mut analyzer = match &args.command {
        Commands::Live { mode: LiveMode::Single { .. } } => {
            info!("Using sequential mode");
            let mut analyzer = HuginnNetTcp::new(1000).with_matcher(matcher.clone());
            if let Some(ref filter_cfg) = filter_config {
                analyzer = analyzer.with_filter(filter_cfg.clone());
                info!("Packet filtering enabled");
            }
            analyzer
        }
        Commands::Live { mode: LiveMode::Parallel { workers, queue_size, .. } } => {
            info!("Using parallel mode with {workers} workers, queue_size={queue_size}");
            let mut analyzer = HuginnNetTcp::new(1000)
                .with_parallel(*workers, *queue_size, 32, 10)
                .with_matcher(matcher.clone());
            if let Some(ref filter_cfg) = filter_config {
                analyzer = analyzer.with_filter(filter_cfg.clone());
                info!("Packet filtering enabled");
            }
            analyzer
        }
        Commands::Pcap { .. } => {
            info!("Using sequential mode for PCAP analysis");
            let mut analyzer = HuginnNetTcp::new(1000).with_matcher(matcher.clone());
            if let Some(ref filter_cfg) = filter_config {
                analyzer = analyzer.with_filter(filter_cfg.clone());
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

    let cancel_signal = Arc::new(AtomicBool::new(false));
    let ctrl_c_signal = cancel_signal.clone();
    let thread_cancel_signal = cancel_signal.clone();

    // Setup Ctrl-C handler with pool shutdown
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

    let analyzer_shared = Arc::new(std::sync::Mutex::new(analyzer));

    thread::spawn(move || {
        let result = {
            let mut analyzer = match analyzer_shared.lock() {
                Ok(a) => a,
                Err(_) => {
                    error!("Failed to lock analyzer");
                    return;
                }
            };
            match &args.command {
                Commands::Live { mode: LiveMode::Single { interface } } => {
                    info!("Starting live capture on interface: {interface}");
                    analyzer.analyze_network(interface, sender, Some(thread_cancel_signal))
                }
                Commands::Live { mode: LiveMode::Parallel { interface, .. } } => {
                    info!("Starting live capture on interface: {interface}");
                    analyzer.analyze_network(interface, sender, Some(thread_cancel_signal))
                }
                Commands::Pcap { file } => {
                    info!("Analyzing PCAP file: {file}");
                    analyzer.analyze_pcap(file, sender, Some(thread_cancel_signal))
                }
            }
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

        match args.format {
            OutputFormat::Human => {
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
            }
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
