use clap::Parser;
use passivetcp_rs::db::Database;
use passivetcp_rs::p0f_output::P0fOutput;
use passivetcp_rs::P0f;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use tracing::{debug, info};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short = 'i', long)]
    interface: String,
    #[arg(short = 'l', long = "log-file")]
    log_file: Option<String>,
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

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");
}

fn main() {
    let args = Args::parse();
    initialize_logging(args.log_file);

    let db = Box::leak(Box::new(Database::default()));
    debug!("Loaded database: {:?}", db);

    let (sender, receiver): (Sender<P0fOutput>, Receiver<P0fOutput>) = mpsc::channel();

    thread::spawn(move || {
        P0f::new(db, 100).analyze_network(&args.interface, sender);
    });

    for output in receiver {
        if let Some(syn) = output.syn {
            info!("{}", syn);
        }
        if let Some(syn_ack) = output.syn_ack {
            info!("{}", syn_ack);
        }
        if let Some(mtu) = output.mtu {
            info!("{}", mtu);
        }
        if let Some(uptime) = output.uptime {
            info!("{}", uptime);
        }
        if let Some(http_request) = output.http_request {
            info!("{}", http_request);
        }
        if let Some(http_response) = output.http_response {
            info!("{}", http_response);
        }
    }
}
