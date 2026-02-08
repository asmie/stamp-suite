use std::{fmt, str::FromStr};

use thiserror::Error;

/// StampModes is an enum that represents the STAMP mode.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum StampModes {
    /// Unauthenticated mode - packets are sent without HMAC authentication.
    Unauthenticated,
    /// Authenticated mode - packets include HMAC for integrity verification.
    Authenticated,
}

/// StampModesError is an enum that represents the error that can occur when parsing a STAMP mode.
#[derive(Error, Debug)]
pub enum StampModesError {
    #[error("Invalid STAMP mode")]
    InvalidStampMode,
}

impl FromStr for StampModes {
    type Err = StampModesError;

    /// Parses a string to a STAMP mode.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "u" => Ok(StampModes::Unauthenticated),
            "a" => Ok(StampModes::Authenticated),
            _ => Err(StampModesError::InvalidStampMode),
        }
    }
}

impl fmt::Display for StampModes {
    /// Formats the STAMP mode.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            StampModes::Unauthenticated => write!(f, "u"),
            StampModes::Authenticated => write!(f, "a"),
        }
    }
}
