//! Stable failure surface of the OpenIDA kernel.
//!
//! Every public operation returns [`Result`], and every failure carries a code
//! that callers can compare instead of parsing prose. The code stays the same
//! when the message is reworded or translated.

use std::fmt;

/// Result of one kernel operation.
pub type Result<T> = std::result::Result<T, IdaError>;

/// Stable failure with a comparable code and a human-readable message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdaError {
    code: &'static str,
    message: String,
}

impl IdaError {
    /// Builds a failure from a stable code and a message.
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    /// A recognised container could not be decoded.
    pub fn parse(message: impl Into<String>) -> Self {
        Self::new("binary/parse", message)
    }

    /// An offset, length or handle falls outside what the file provides.
    pub fn range(message: impl Into<String>) -> Self {
        Self::new("binary/range", message)
    }

    /// The file or feature is not supported by this build.
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new("binary/unsupported", message)
    }

    /// The file could not be read or written.
    pub fn io(message: impl Into<String>) -> Self {
        Self::new("binary/io", message)
    }

    /// The stable code, such as `binary/parse`.
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// The human-readable message without the code prefix.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for IdaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for IdaError {}

impl From<std::io::Error> for IdaError {
    fn from(error: std::io::Error) -> Self {
        Self::io(error.to_string())
    }
}

impl From<data_binary_inspect::InspectError> for IdaError {
    fn from(error: data_binary_inspect::InspectError) -> Self {
        Self::new(error.code(), error.message().to_string())
    }
}

impl From<data_binary_container::ContainerError> for IdaError {
    fn from(error: data_binary_container::ContainerError) -> Self {
        Self::new(error.code(), error.message().to_string())
    }
}
