use clap::ValueEnum;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::EnvFilter;

#[derive(ValueEnum, Debug, Clone, Default)]
pub enum OutputFormat {
    #[default]
    Human,
    Json,
}

#[derive(clap::Args, Debug)]
pub struct FilterOptions {
    #[arg(short = 'p', long = "port")]
    pub port: Option<u16>,

    #[arg(short = 'I', long = "ip")]
    pub ip: Option<String>,
}

pub fn initialize_logging(log_file: Option<String>, use_stderr: bool) {
    let file_appender = if let Some(log_file) = log_file {
        RollingFileAppender::new(Rotation::NEVER, ".", log_file)
            .with_max_level(tracing::Level::INFO)
    } else {
        RollingFileAppender::new(Rotation::NEVER, ".", "default.log")
            .with_max_level(tracing::Level::INFO)
    };

    let result = if use_stderr {
        let writer = std::io::stderr
            .with_max_level(tracing::Level::INFO)
            .and(file_appender);
        tracing::subscriber::set_global_default(
            fmt()
                .with_env_filter(EnvFilter::from_default_env())
                .with_writer(writer)
                .finish(),
        )
    } else {
        let writer = std::io::stdout
            .with_max_level(tracing::Level::INFO)
            .and(file_appender);
        tracing::subscriber::set_global_default(
            fmt()
                .with_env_filter(EnvFilter::from_default_env())
                .with_writer(writer)
                .finish(),
        )
    };

    if let Err(e) = result {
        eprintln!("Failed to set subscriber: {e}");
        std::process::exit(1);
    }
}
