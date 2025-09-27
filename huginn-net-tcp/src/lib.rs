#![forbid(unsafe_code)]

pub use huginn_net_db as db;
pub use huginn_net_db::tcp;

// TCP processing modules
pub mod tcp_process;
pub mod mtu;
pub mod ttl;
pub mod uptime;
pub mod window_size;
pub mod ip_options;

pub mod error;
pub mod observable;
pub mod display;

// Placeholder module for future TCP-specific processing built on top of huginn-net-db
