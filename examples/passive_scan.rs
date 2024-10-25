use clap::Parser;
use log::debug;
use passivetcp::PassiveTcpFingerprinter;
use passivetcp::db::Database;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    interface: String,
}

fn main() {
    let args = Args::parse();
    let interface_name = args.interface;

    let db = Database::default();
    debug!("Loaded database: {:?}", db);
    let fingerprinting_tool = PassiveTcpFingerprinter::new(&db);

    fingerprinting_tool.start_capture(&interface_name);
}