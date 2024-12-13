use clap::Parser;
use log::debug;
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
    let args = Args::parse();

    let db = Box::leak(Box::new(Database::default()));
    debug!("Loaded database: {:?}", db);

    let mut p0f = P0f::new(db, 100);

    let (sender, receiver) = mpsc::channel();

    thread::spawn(move || {
        p0f.analyze_network(&args.interface, sender);
    });

    for output in receiver {
        if let Some(syn) = output.syn {
            println!("{}", syn);
        }
        if let Some(syn_ack) = output.syn_ack {
            println!("{}", syn_ack);
        }
        if let Some(mtu) = output.mtu {
            println!("{}", mtu);
        }
        if let Some(uptime) = output.uptime {
            println!("{}", uptime);
        }
    }
}
