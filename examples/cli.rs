#[path = "support/mod.rs"]
mod support;
use support::{FilterOptions, initialize_logging};

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

    initialize_logging(args.log_file);

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

    thread::spawn(move || {
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
    });

    for output in receiver {
        if cancel_signal.load(Ordering::Relaxed) {
            info!("Shutdown signal received, stopping result processing");
            break;
        }

        print_human(&output);
    }

    info!("Analysis shutdown completed");
}

fn print_human(output: &FingerprintResult) {
    if let Some(syn) = &output.tcp_syn {
        let note = output
            .tcp_mtu
            .as_ref()
            .map(|mtu| format!("mtu {}", mtu.mtu));
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
    if let Some(syn_ack) = &output.tcp_syn_ack {
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
    if output.tcp_syn.is_none() {
        if let Some(mtu) = &output.tcp_mtu {
            support::print_event(
                "TCP",
                "1;36",
                "MTU",
                &support::endpoint(&mtu.source.ip, mtu.source.port),
                &support::endpoint(&mtu.destination.ip, mtu.destination.port),
                &mtu.mtu.to_string(),
                mtu.link.link.as_deref().unwrap_or("???"),
                detail_color(mtu.link.link.is_some()),
                None,
            );
        }
    }
    if let Some(uptime) = &output.tcp_client_uptime {
        print_uptime(uptime);
    }
    if let Some(uptime) = &output.tcp_server_uptime {
        print_uptime(uptime);
    }
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
    if let Some(tls) = &output.tls_client {
        let to = tls
            .sig
            .sni
            .clone()
            .unwrap_or_else(|| support::endpoint(&tls.destination.ip, tls.destination.port));
        support::print_event(
            "TLS",
            "1;35",
            &tls_label(&tls.sig.version),
            &support::endpoint(&tls.source.ip, tls.source.port),
            &to,
            tls.sig.ja4.full.value(),
            "—",
            "2",
            None,
        );
    }
}

fn print_uptime(uptime: &huginn_net::UptimeOutput) {
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

fn os_label(matched: &huginn_net::OSQualityMatched) -> String {
    matched.os.as_ref().map_or_else(
        || "???".to_string(),
        |os| support::with_variant(&os.name, os.variant.as_deref()),
    )
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

fn tls_label(version: &impl std::fmt::Display) -> String {
    match version.to_string().as_str() {
        "13" => "1.3".to_string(),
        "12" => "1.2".to_string(),
        "11" => "1.1".to_string(),
        "10" => "1.0".to_string(),
        "s3" => "ssl3".to_string(),
        "s2" => "ssl2".to_string(),
        other => other.to_string(),
    }
}

fn detail_color(matched: bool) -> &'static str {
    if matched { "1;32" } else { "2" }
}
