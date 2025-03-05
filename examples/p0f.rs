use clap::Parser;
use log::{debug, info};
use log4rs::append::console::ConsoleAppender;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::Config;
use passivetcp_rs::db::Database;
use passivetcp_rs::P0f;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use passivetcp_rs::p0f_output::P0fOutput;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short = 'i', long)]
    interface: String,
    #[arg(short = 'l', long = "log-file")]
    log_file: Option<String>,
}

fn initialize_logging(log_file: Option<String>) {
    let pattern = "{d} - {l} - {m}{n}";
    let console = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(pattern)))
        .build();

    let config = if let Some(log_file) = log_file {
        let file = FileAppender::builder()
            .encoder(Box::new(PatternEncoder::new(pattern)))
            .build(log_file)
            .expect("Failed to create log file appender");

        Config::builder()
            .appender(Appender::builder().build("console", Box::new(console)))
            .appender(Appender::builder().build("file", Box::new(file)))
            .build(
                Root::builder()
                    .appender("console")
                    .appender("file")
                    .build(log::LevelFilter::Info),
            )
            .expect("Failed to build log4rs config")
    } else {
        Config::builder()
            .appender(Appender::builder().build("console", Box::new(console)))
            .build(
                Root::builder()
                    .appender("console")
                    .build(log::LevelFilter::Info),
            )
            .expect("Failed to build log4rs config")
    };

    log4rs::init_config(config).expect("Failed to initialize log4rs");
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
