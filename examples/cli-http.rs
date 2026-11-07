#[path = "support/mod.rs"]
mod support;
use support::{Commands, FilterOptions, LiveMode, OutputFormat, initialize_logging};

use clap::Parser;
use huginn_net_db::{HttpDatabase, SharedHttpSignatureMatcher};
use huginn_net_http::matcher_api::HttpMatcher;
use huginn_net_http::{FilterConfig, HttpAnalysisResult, HuginnNetHttp, IpFilter, PortFilter};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
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

    /// TLS key log file (SSLKEYLOGFILE format) used to decrypt HTTP/2 over TLS for Akamai
    /// fingerprints. Read once for `pcap`, followed for `live`.
    #[cfg(feature = "akamai-keylog")]
    #[arg(long = "keylog")]
    keylog: Option<String>,

    /// How long a connection waits for its key log secret, in milliseconds.
    #[cfg(feature = "akamai-keylog")]
    #[arg(long = "keylog-wait", default_value = "2000")]
    keylog_wait: u64,
}

/// Adds key log decryption to the analyzer when `--keylog` was given.
#[cfg(feature = "akamai-keylog")]
fn with_keylog(
    analyzer: HuginnNetHttp,
    keylog: Option<&str>,
    wait_ms: u64,
    live: bool,
) -> Option<HuginnNetHttp> {
    use huginn_net_http::{KeylogConfig, KeylogSource};
    let Some(path) = keylog else {
        return Some(analyzer);
    };
    let source = if live {
        KeylogSource::Follow(path.into())
    } else {
        KeylogSource::File(path.into())
    };
    let config =
        KeylogConfig::new(source).pending_timeout(std::time::Duration::from_millis(wait_ms.max(1)));
    match analyzer.with_keylog(config) {
        Ok(analyzer) => {
            info!("Key log decryption enabled ({path})");
            Some(analyzer)
        }
        Err(e) => {
            error!("Cannot use key log: {e}");
            None
        }
    }
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

/// Prints the key log counters when the analysis ends.
fn log_keylog_stats(analyzer: &HuginnNetHttp) {
    #[cfg(feature = "akamai-keylog")]
    info!("Key log stats: {:?}", analyzer.keylog_stats());
    #[cfg(not(feature = "akamai-keylog"))]
    let _ = analyzer;
}

fn main() {
    let args = Args::parse();
    let format = args.format;

    initialize_logging(args.log_file, matches!(format, OutputFormat::Json));

    #[cfg(not(feature = "json"))]
    if matches!(format, OutputFormat::Json) {
        error!("error: --format json requires the `json` feature");
        info!("hint:  cargo run --example cli-http --features full,json -- --format json ...");
        std::process::exit(1);
    }

    info!("Starting HTTP-only capture example");

    let (sender, receiver): (Sender<HttpAnalysisResult>, Receiver<HttpAnalysisResult>) = channel();

    let db = match HttpDatabase::load_default() {
        Ok(db) => Arc::new(db),
        Err(e) => {
            error!("Failed to load default HTTP database: {e}");
            return;
        }
    };
    debug!("Loaded p0f HTTP database successfully");
    let matcher: Arc<dyn HttpMatcher + Send + Sync> = Arc::new(SharedHttpSignatureMatcher::new(db));

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

    let analysis = thread::spawn(move || {
        let filter_config = build_filter(&args.filter);
        #[cfg(feature = "akamai-keylog")]
        let keylog = args.keylog.clone();
        #[cfg(feature = "akamai-keylog")]
        let keylog_wait = args.keylog_wait;

        match args.command {
            Commands::Live { mode: LiveMode::Single { interface } } => {
                info!("Initializing HTTP analyzer in sequential mode");
                let mut analyzer = HuginnNetHttp::new(1000).with_matcher(matcher.clone());
                if let Some(ref filter_cfg) = filter_config {
                    analyzer = analyzer.with_filter(filter_cfg.clone());
                    info!("Packet filtering enabled");
                }

                #[cfg(feature = "akamai-keylog")]
                let Some(analyzer) = with_keylog(analyzer, keylog.as_deref(), keylog_wait, true)
                else {
                    return;
                };
                #[cfg(feature = "akamai-keylog")]
                let mut analyzer = analyzer;
                info!("Starting HTTP live capture on interface: {interface}");
                if let Err(e) =
                    analyzer.analyze_network(&interface, sender, Some(thread_cancel_signal))
                {
                    error!("HTTP analysis failed: {e}");
                }
                log_keylog_stats(&analyzer);
            }
            Commands::Live { mode: LiveMode::Parallel { interface, workers, queue_size } } => {
                info!(
                    "Initializing HTTP analyzer with {workers} worker threads (flow-based routing)"
                );
                let mut analyzer = HuginnNetHttp::new(1000)
                    .with_parallel(workers, queue_size, 16, 10)
                    .with_matcher(matcher.clone());
                if let Some(ref filter_cfg) = filter_config {
                    analyzer = analyzer.with_filter(filter_cfg.clone());
                    info!("Packet filtering enabled");
                }

                #[cfg(feature = "akamai-keylog")]
                let Some(analyzer) = with_keylog(analyzer, keylog.as_deref(), keylog_wait, true)
                else {
                    return;
                };
                #[cfg(feature = "akamai-keylog")]
                let mut analyzer = analyzer;
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
                log_keylog_stats(&analyzer);
            }
            Commands::Pcap { file } => {
                info!("Initializing HTTP analyzer in sequential mode for PCAP analysis");
                let mut analyzer = HuginnNetHttp::new(1000).with_matcher(matcher.clone());
                if let Some(ref filter_cfg) = filter_config {
                    analyzer = analyzer.with_filter(filter_cfg.clone());
                    info!("Packet filtering enabled");
                }

                #[cfg(feature = "akamai-keylog")]
                let Some(analyzer) = with_keylog(analyzer, keylog.as_deref(), keylog_wait, false)
                else {
                    return;
                };
                #[cfg(feature = "akamai-keylog")]
                let mut analyzer = analyzer;
                info!("Analyzing PCAP file: {file}");
                if let Err(e) = analyzer.analyze_pcap(&file, sender, Some(thread_cancel_signal)) {
                    error!("HTTP analysis failed: {e}");
                }
                log_keylog_stats(&analyzer);
            }
        }
    });

    for output in receiver {
        if cancel_signal.load(Ordering::Relaxed) {
            info!("Shutdown signal received, stopping result processing");
            break;
        }

        match format {
            OutputFormat::Human => {
                if let Some(http_request) = output.http_request {
                    info!("{http_request}");
                }
                if let Some(http_response) = output.http_response {
                    info!("{http_response}");
                }
                #[cfg(any(feature = "akamai-cleartext", feature = "akamai-keylog"))]
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
