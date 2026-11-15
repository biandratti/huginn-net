#![forbid(unsafe_code)]

#[path = "support/mod.rs"]
mod support;
use support::{FilterOptions, initialize_logging};

use clap::{Parser, Subcommand};
#[cfg(feature = "db")]
use huginn_net::Database;
use huginn_net::output::FingerprintResult;
use huginn_net::{FilterConfig, HuginnNet, IpFilter, PortFilter};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use tracing::{error, info};

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

    #[cfg(feature = "db")]
    let db = match Database::load_default() {
        Ok(db) => db,
        Err(e) => {
            error!("Failed to load default p0f database: {e}");
            return;
        }
    };
    #[cfg(feature = "db")]
    tracing::debug!("Loaded p0f TCP+HTTP database successfully");

    thread::spawn(move || {
        let filter_config = build_filter(&args.filter);

        #[cfg(feature = "db")]
        let built = HuginnNet::new(Some(&db), 100, None);
        #[cfg(not(feature = "db"))]
        let built = HuginnNet::new_observable(100, None);

        let mut analyzer = match built {
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
    #[cfg(feature = "tcp-syn")]
    if let Some(syn) = &output.tcp_syn {
        support::Event::new(support::Kind::Syn)
            .between(&syn.source.ip, syn.source.port, &syn.destination.ip, syn.destination.port)
            .signature(syn.sig.to_string())
            .matched(support::os_match(
                syn.os_matched
                    .os
                    .as_ref()
                    .map(|os| (os.name.as_str(), os.variant.as_deref())),
            ))
            .emit();
    }
    #[cfg(feature = "tcp-mtu")]
    if let Some(mtu) = &output.tcp_mtu {
        support::Event::new(support::Kind::Mtu)
            .between(&mtu.source.ip, mtu.source.port, &mtu.destination.ip, mtu.destination.port)
            .signature(mtu.mtu.to_string())
            .matched(support::link(mtu.link.link.as_deref()))
            .emit();
    }
    #[cfg(feature = "tcp-syn-ack")]
    if let Some(syn_ack) = &output.tcp_syn_ack {
        support::Event::new(support::Kind::SynAck)
            .between(
                &syn_ack.source.ip,
                syn_ack.source.port,
                &syn_ack.destination.ip,
                syn_ack.destination.port,
            )
            .signature(syn_ack.sig.to_string())
            .matched(support::os_match(
                syn_ack
                    .os_matched
                    .os
                    .as_ref()
                    .map(|os| (os.name.as_str(), os.variant.as_deref())),
            ))
            .emit();
    }
    #[cfg(feature = "tcp-uptime")]
    {
        if let Some(uptime) = &output.tcp_client_uptime {
            emit_uptime(uptime);
        }
        if let Some(uptime) = &output.tcp_server_uptime {
            emit_uptime(uptime);
        }
    }
    #[cfg(feature = "http-p0f-request")]
    if let Some(request) = &output.http_request {
        support::Event::new(support::Kind::HttpRequest)
            .between(
                &request.source.ip,
                request.source.port,
                &request.destination.ip,
                request.destination.port,
            )
            .signature(request.sig.to_string())
            .matched(support::product(request.browser_matched.browser.as_ref().map(|browser| {
                (browser.name.as_str(), browser.family.as_deref(), browser.variant.as_deref())
            })))
            .note_opt(request.lang.as_deref())
            .emit();
    }
    #[cfg(feature = "http-p0f-response")]
    if let Some(response) = &output.http_response {
        support::Event::new(support::Kind::HttpResponse)
            .between(
                &response.source.ip,
                response.source.port,
                &response.destination.ip,
                response.destination.port,
            )
            .signature(response.sig.to_string())
            .matched(support::product(response.web_server_matched.web_server.as_ref().map(
                |server| {
                    (server.name.as_str(), server.family.as_deref(), server.variant.as_deref())
                },
            )))
            .emit();
    }
    if let Some(tls) = &output.tls_client {
        let from = support::endpoint(&tls.source.ip, tls.source.port);
        let to = tls
            .sig
            .sni
            .clone()
            .unwrap_or_else(|| support::endpoint(&tls.destination.ip, tls.destination.port));
        support::Event::new(support::Kind::tls(&tls.sig.version))
            .flow(&from, &to)
            .signature(tls.sig.ja4.full.value())
            .emit();
        #[cfg(feature = "tls-stable-v1")]
        support::Event::new(support::Kind::TlsS1)
            .flow(&from, &to)
            .signature(tls.sig.ja4_stable_v1.full.value())
            .emit();
    }
}

#[cfg(feature = "tcp-uptime")]
fn emit_uptime(uptime: &huginn_net::UptimeOutput) {
    let kind = match uptime.role {
        huginn_net::UptimeRole::Client => support::Kind::UptimeClient,
        huginn_net::UptimeRole::Server => support::Kind::UptimeServer,
    };
    support::Event::new(kind)
        .between(
            &uptime.source.ip,
            uptime.source.port,
            &uptime.destination.ip,
            uptime.destination.port,
        )
        .signature(format!("{}d {}h {}m", uptime.days, uptime.hours, uptime.min))
        .emit();
}
