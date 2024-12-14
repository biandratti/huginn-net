use clap::Parser;
use log::{debug, info};
use passivetcp_rs::db::Database;
use passivetcp_rs::P0f;
use std::sync::mpsc;
use std::thread;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    interface: String,
}

fn main() {
    env_logger::init();
    let args = Args::parse();

    let db = Box::leak(Box::new(Database::default()));
    debug!("Loaded database: {:?}", db);

    let (sender, receiver) = mpsc::channel();

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
    }
}
