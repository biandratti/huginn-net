#[path = "support/mod.rs"]
mod support;
use support::{Commands, FilterOptions, LiveMode, initialize_logging};

use clap::Parser;
use huginn_net_db::{SharedTcpSignatureMatcher, TcpDatabase};
use huginn_net_tcp::matcher_api::TcpMatcher;
use huginn_net_tcp::{FilterConfig, HuginnNetTcp, IpFilter, PortFilter, TcpAnalysisResult};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
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

    initialize_logging(args.log_file);

    let (sender, receiver): (Sender<TcpAnalysisResult>, Receiver<TcpAnalysisResult>) =
        mpsc::channel();

    let db = match TcpDatabase::load_default() {
        Ok(db) => Arc::new(db),
        Err(e) => {
            error!("Failed to load default TCP database: {e}");
            return;
        }
    };
    debug!("Loaded p0f TCP database successfully");
    let matcher: Arc<dyn TcpMatcher + Send + Sync> = Arc::new(SharedTcpSignatureMatcher::new(db));

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

        print_tcp(&output);

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

fn print_tcp(output: &TcpAnalysisResult) {
    if let Some(syn) = &output.syn {
        let note = output.mtu.as_ref().map(|mtu| format!("mtu {}", mtu.mtu));
        support::print_event(
            "TCP",
            "1;36",
            "SYN",
            &support::endpoint(&syn.source.ip, syn.source.port),
            &support::endpoint(&syn.destination.ip, syn.destination.port),
            &syn.sig.to_string(),
            &os_label(&syn.os_matched),
            detail_color(syn.os_matched.os.is_some()),
            note.as_deref(),
        );
    }
    if let Some(syn_ack) = &output.syn_ack {
        support::print_event(
            "TCP",
            "1;36",
            "SYNACK",
            &support::endpoint(&syn_ack.source.ip, syn_ack.source.port),
            &support::endpoint(&syn_ack.destination.ip, syn_ack.destination.port),
            &syn_ack.sig.to_string(),
            &os_label(&syn_ack.os_matched),
            detail_color(syn_ack.os_matched.os.is_some()),
            None,
        );
    }
    if output.syn.is_none() {
        if let Some(mtu) = &output.mtu {
            print_mtu(mtu);
        }
    }
    if let Some(uptime) = &output.client_uptime {
        print_uptime(uptime);
    }
    if let Some(uptime) = &output.server_uptime {
        print_uptime(uptime);
    }
}

fn print_mtu(mtu: &huginn_net_tcp::MTUOutput) {
    let matched = mtu.link.link.as_deref().unwrap_or("???");
    support::print_event(
        "TCP",
        "1;36",
        "MTU",
        &support::endpoint(&mtu.source.ip, mtu.source.port),
        &support::endpoint(&mtu.destination.ip, mtu.destination.port),
        &mtu.mtu.to_string(),
        matched,
        detail_color(mtu.link.link.is_some()),
        None,
    );
}

fn print_uptime(uptime: &huginn_net_tcp::UptimeOutput) {
    let role = uptime.role.to_string();
    support::print_event(
        "TCP",
        "1;36",
        "UPTIME",
        &support::endpoint(&uptime.source.ip, uptime.source.port),
        &support::endpoint(&uptime.destination.ip, uptime.destination.port),
        &format!("{}d {}h {}m", uptime.days, uptime.hours, uptime.min),
        "—",
        "2",
        Some(&role),
    );
}

fn os_label(matched: &huginn_net_tcp::OSQualityMatched) -> String {
    matched.os.as_ref().map_or_else(
        || "???".to_string(),
        |os| support::with_variant(&os.name, os.variant.as_deref()),
    )
}

fn detail_color(matched: bool) -> &'static str {
    if matched { "1;32" } else { "2" }
}
