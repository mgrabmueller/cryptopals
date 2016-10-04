// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

//! Errors used in the crate and the corresponding binaries.

use std::io;
use std::fmt;
use std::error;

/// Errors that may happen during operation.
#[derive(Debug)]
pub enum Error {
    /// IO Error.
    Io(io::Error),
    /// Hex string contains invalid character.
    InvalidHexChar(char),
    /// Hex string has odd length.
    InvalidHexLength,
    /// Base64 string contains invalid character.
    InvalidBase64Char(char),
    /// Base64 string has invalid length.
    InvalidBase64Length,
    /// Base64 string has invalid padding.
    InvalidBase64Padding,
    /// Some unimplemented functionality was requested.
    Unimplemented(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref err) =>
                write!(f, "IO error: {}", err),
            Error::InvalidHexChar(ref ch) =>
                write!(f, "Invalid hex character: {:?}", ch),
            Error::InvalidHexLength =>
                write!(f, "Hex string has odd length"),
            Error::InvalidBase64Char(ref ch) =>
                write!(f, "Invalid base64 character: {:?}", ch),
            Error::InvalidBase64Length =>
                write!(f, "Invalid base64 string length"),
            Error::InvalidBase64Padding =>
                write!(f, "Invalid base64 string padding"),
            Error::Unimplemented(ref err) =>
                write!(f, "unimplemented: {}", err),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Io(ref err) => err.description(),
            Error::InvalidHexChar(_) => "invalid hex character",
            Error::InvalidHexLength => "hex string has odd length",
            Error::InvalidBase64Char(_) => "invalid base64 character",
            Error::InvalidBase64Length => "invalid base64 string length",
            Error::InvalidBase64Padding => "invalid base64 string padding",
            Error::Unimplemented(_) => "unimplemented",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Io(ref err) => Some(err),
            Error::InvalidHexChar(_) => None,
            Error::InvalidHexLength => None,
            Error::InvalidBase64Char(_) => None,
            Error::InvalidBase64Length => None,
            Error::InvalidBase64Padding => None,
            Error::Unimplemented(_) => None,
       } 
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}
