use std::{fmt, str::FromStr};

use thiserror::Error;

/// StampModes is an enum that represents the STAMP mode.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum StampModes {
    Unauthenticated,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stamp_modes_parsing() {
        assert_eq!(
            "u".parse::<StampModes>().unwrap(),
            StampModes::Unauthenticated
        );
        assert_eq!(
            "a".parse::<StampModes>().unwrap(),
            StampModes::Authenticated
        );
        assert!("INVALID".parse::<StampModes>().is_err());
    }

    #[test]
    fn test_stamp_modes_display() {
        assert_eq!(StampModes::Unauthenticated.to_string(), "u");
        assert_eq!(StampModes::Authenticated.to_string(), "a");
    }
}
