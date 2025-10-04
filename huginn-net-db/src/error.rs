use thiserror::Error;

/// Error handling for database parsing and operations.
#[derive(Error, Debug)]
pub enum DatabaseError {
    /// An error occurred while parsing the p0f database format.
    #[error("Parse error: {0}")]
    Parse(String),

    /// Configuration is missing or invalid.
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
}
