#[path = "support/mod.rs"]
mod support;
use support::{FilterOptions, OutputFormat, initialize_logging};

use clap::{Parser, Subcommand};
use huginn_net::output::FingerprintResult;
use huginn_net::{Database, FilterConfig, HuginnNet, IpFilter, PortFilter};
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

    /// Log file path
    #[arg(short = 'l', long = "log-file")]
    log_file: Option<String>,

    #[arg(long, value_enum, default_value = "human")]
    format: OutputFormat,

    /// TLS key log file (SSLKEYLOGFILE format) used to decrypt HTTP/2 over TLS for Akamai
    /// fingerprints. Read once for `pcap`, followed for `live`.
    #[cfg(feature = "http-akamai-keylog")]
    #[arg(long = "keylog")]
    keylog: Option<String>,

    /// How long a connection waits for its key log secret, in milliseconds.
    #[cfg(feature = "http-akamai-keylog")]
    #[arg(long = "keylog-wait", default_value = "2000")]
    keylog_wait: u64,
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
    let format = args.format;

    initialize_logging(args.log_file, matches!(format, OutputFormat::Json));

    #[cfg(not(feature = "json"))]
    if matches!(format, OutputFormat::Json) {
        error!("error: --format json requires the `json` feature");
        info!("hint:  cargo run --example cli --features full,json -- --format json ...");
        std::process::exit(1);
    }

    let (sender, receiver): (Sender<FingerprintResult>, Receiver<FingerprintResult>) =
        mpsc::channel();

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

    let db = match Database::load_default() {
        Ok(db) => db,
        Err(e) => {
            error!("Failed to load default p0f database: {e}");
            return;
        }
    };
    debug!("Loaded p0f TCP+HTTP database successfully");

    let analysis = thread::spawn(move || {
        let filter_config = build_filter(&args.filter);

        let mut analyzer = match HuginnNet::new(Some(&db), 100, None) {
            Ok(analyzer) => analyzer,
            Err(e) => {
                error!("Failed to create HuginnNet analyzer: {e}");
                return;
            }
        };

        if let Some(ref filter_cfg) = filter_config {
            analyzer = analyzer.with_filter(filter_cfg.clone());
        }

        #[cfg(feature = "http-akamai-keylog")]
        if let Some(path) = args.keylog.as_deref() {
            use huginn_net::{KeylogConfig, KeylogSource};
            let source = match args.command {
                Commands::Live { .. } => KeylogSource::Follow(path.into()),
                Commands::Pcap { .. } => KeylogSource::File(path.into()),
            };
            let config = KeylogConfig::new(source)
                .pending_timeout(std::time::Duration::from_millis(args.keylog_wait.max(1)));
            analyzer = match analyzer.with_keylog(config) {
                Ok(analyzer) => {
                    info!("Key log decryption enabled ({path})");
                    analyzer
                }
                Err(e) => {
                    error!("Cannot use key log: {e}");
                    return;
                }
            };
        }

        let result = match args.command {
            Commands::Live { interface } => {
                info!("Starting live capture on interface: {interface}");
                analyzer.analyze_network(&interface, sender, Some(thread_cancel_signal.clone()))
            }
            Commands::Pcap { file } => {
                info!("Analyzing PCAP file: {file}");
                analyzer.analyze_pcap(&file, sender, Some(thread_cancel_signal))
            }
        };

        if let Err(e) = result {
            error!("Analysis failed: {e}");
        }
        #[cfg(feature = "http-akamai-keylog")]
        info!("Key log stats: {:?}", analyzer.keylog_stats());
    });

    for output in receiver {
        if cancel_signal.load(Ordering::Relaxed) {
            info!("Shutdown signal received, stopping result processing");
            break;
        }

        match format {
            OutputFormat::Human => {
                if let Some(tcp_syn) = output.tcp_syn {
                    info!("{tcp_syn}");
                }
                if let Some(tcp_syn_ack) = output.tcp_syn_ack {
                    info!("{tcp_syn_ack}");
                }
                if let Some(tcp_mtu) = output.tcp_mtu {
                    info!("{tcp_mtu}");
                }
                if let Some(tcp_client_uptime) = output.tcp_client_uptime {
                    info!("{tcp_client_uptime}");
                }
                if let Some(tcp_server_uptime) = output.tcp_server_uptime {
                    info!("{tcp_server_uptime}");
                }
                if let Some(http_request) = output.http_request {
                    info!("{http_request}");
                }
                if let Some(http_response) = output.http_response {
                    info!("{http_response}");
                }
                if let Some(tls_client) = output.tls_client {
                    info!("{tls_client}");
                }
                #[cfg(any(feature = "http-akamai-cleartext", feature = "http-akamai-keylog"))]
                if let Some(http_akamai) = output.http_akamai {
                    info!("{http_akamai}");
                }
            }
            OutputFormat::Json =>
            {
                #[cfg(feature = "json")]
                if !output.is_empty() {
                    match serde_json::to_string(&output) {
                        Ok(json) => println!("{json}"),
                        Err(e) => error!("Failed to serialize output: {e}"),
                    }
                }
            }
        }
    }

    // Wait for the analysis thread so its final messages (key log stats) are printed.
    let _ = analysis.join();
    info!("Analysis shutdown completed");
}
