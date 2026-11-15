#[path = "support/mod.rs"]
mod support;
use support::{Commands, FilterOptions, LiveMode, initialize_logging};

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

    thread::spawn(move || {
        let filter_config = build_filter(&args.filter);

        match args.command {
            Commands::Live { mode: LiveMode::Single { interface } } => {
                info!("Initializing HTTP analyzer in sequential mode");
                let mut analyzer = HuginnNetHttp::new(1000).with_matcher(matcher.clone());
                if let Some(ref filter_cfg) = filter_config {
                    analyzer = analyzer.with_filter(filter_cfg.clone());
                    info!("Packet filtering enabled");
                }

                info!("Starting HTTP live capture on interface: {interface}");
                if let Err(e) =
                    analyzer.analyze_network(&interface, sender, Some(thread_cancel_signal))
                {
                    error!("HTTP analysis failed: {e}");
                }
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
            Commands::Pcap { file } => {
                info!("Initializing HTTP analyzer in sequential mode for PCAP analysis");
                let mut analyzer = HuginnNetHttp::new(1000).with_matcher(matcher.clone());
                if let Some(ref filter_cfg) = filter_config {
                    analyzer = analyzer.with_filter(filter_cfg.clone());
                    info!("Packet filtering enabled");
                }

                info!("Analyzing PCAP file: {file}");
                if let Err(e) = analyzer.analyze_pcap(&file, sender, Some(thread_cancel_signal)) {
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

        print_http(&output);
    }

    info!("Analysis shutdown completed");
}

fn print_http(output: &HttpAnalysisResult) {
    if let Some(request) = &output.http_request {
        support::print_event(
            "HTTP",
            "1;34",
            "REQ",
            &support::endpoint(&request.source.ip, request.source.port),
            &support::endpoint(&request.destination.ip, request.destination.port),
            &request.sig.to_string(),
            &product_label(request.browser_matched.browser.as_ref().map(|browser| {
                (browser.name.as_str(), browser.family.as_deref(), browser.variant.as_deref())
            })),
            detail_color(request.browser_matched.browser.is_some()),
            request.lang.as_deref(),
        );
    }
    if let Some(response) = &output.http_response {
        support::print_event(
            "HTTP",
            "1;34",
            "RESP",
            &support::endpoint(&response.source.ip, response.source.port),
            &support::endpoint(&response.destination.ip, response.destination.port),
            &response.sig.to_string(),
            &product_label(
                response
                    .web_server_matched
                    .web_server
                    .as_ref()
                    .map(|server| {
                        (server.name.as_str(), server.family.as_deref(), server.variant.as_deref())
                    }),
            ),
            detail_color(response.web_server_matched.web_server.is_some()),
            None,
        );
    }
}

fn product_label(matched: Option<(&str, Option<&str>, Option<&str>)>) -> String {
    matched.map_or_else(
        || "???".to_string(),
        |(name, family, variant)| {
            if name.is_empty() {
                support::with_variant(family.unwrap_or("???"), variant)
            } else {
                support::with_variant(name, variant)
            }
        },
    )
}

fn detail_color(matched: bool) -> &'static str {
    if matched { "1;32" } else { "2" }
}
