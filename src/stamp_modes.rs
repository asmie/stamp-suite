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

    #[test]
    fn test_stamp_modes_case_sensitive() {
        // Uppercase should fail
        assert!("U".parse::<StampModes>().is_err());
        assert!("A".parse::<StampModes>().is_err());
    }

    #[test]
    fn test_stamp_modes_empty_string() {
        assert!("".parse::<StampModes>().is_err());
    }

    #[test]
    fn test_stamp_modes_whitespace() {
        assert!(" u".parse::<StampModes>().is_err());
        assert!("u ".parse::<StampModes>().is_err());
        assert!(" a ".parse::<StampModes>().is_err());
    }

    #[test]
    fn test_stamp_modes_multiple_chars() {
        // Multiple characters should fail
        assert!("ua".parse::<StampModes>().is_err());
        assert!("au".parse::<StampModes>().is_err());
        assert!("uu".parse::<StampModes>().is_err());
    }

    #[test]
    fn test_stamp_modes_roundtrip() {
        let unauth = "u".parse::<StampModes>().unwrap();
        let unauth_str = unauth.to_string();
        let unauth_again = unauth_str.parse::<StampModes>().unwrap();
        assert_eq!(unauth, unauth_again);

        let auth = "a".parse::<StampModes>().unwrap();
        let auth_str = auth.to_string();
        let auth_again = auth_str.parse::<StampModes>().unwrap();
        assert_eq!(auth, auth_again);
    }
}
