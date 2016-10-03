// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.

use std::io;
use std::fmt;
use std::error;

/// Errors that may happen during operation.
#[derive(Debug)]
pub enum Error {
    /// IO Error.
    Io(io::Error),
    /// Hex string contained invalid character.
    InvalidHexChar(char),
    /// Hex string has odd length.
    InvalidHexLength,
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
            Error::Unimplemented(_) => "unimplemented",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Io(ref err) => Some(err),
            Error::InvalidHexChar(_) => None,
            Error::InvalidHexLength => None,
            Error::Unimplemented(_) => None,
       } 
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}
