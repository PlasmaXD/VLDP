//! Error types for VLDP

use std::fmt::{Display, Formatter};

/// Generic error class capturing all VLDP errors:
/// - Conversion error from value to field elemnt
/// - Marlin related error
/// - Parsing related error
#[derive(Debug)]
pub enum GenericError {
    ConversionError,
    ParseError(String),
    MarlinError(String),
}
impl Display for GenericError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            GenericError::ConversionError => write!(
                f,
                "You tried to convert a value to a field element, but this failed!"
            ),
            GenericError::MarlinError(e) => write!(f, "An error using Marlin occurred: {}", e),
            GenericError::ParseError(e) => write!(f, "An error occured during parsing: {}", e),
        }
    }
}

impl std::error::Error for GenericError {}

/// Class capturing client side errors:
/// - Unobtained value: tried to use a value from storage that has not yet been computed
#[derive(Debug)]
pub enum ClientError {
    UnobtainedValue,
}

impl Display for ClientError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::UnobtainedValue => write!(
                f,
                "You tried to use a value from storage, but this value has not yet been obtained."
            ),
        }
    }
}

impl std::error::Error for ClientError {}
