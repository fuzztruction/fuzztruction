use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("ConfigurationError: {0}")]
    ConfigurationError(String),
    #[error("Error: {0}")]
    DisplayError(String),
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}
