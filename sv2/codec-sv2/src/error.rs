//! # Error Handling and Result Types
//!
//! This module defines error types and utilities for handling errors in the `codec_sv2` module.
//! It includes the [`Error`] enum for representing various errors and a `Result` type alias for
//! convenience.

use core::fmt;
#[cfg(feature = "noise_sv2")]
use noise_sv2::{AeadError, Error as NoiseError};

/// A type alias for results returned by the `codec_sv2` modules.
///
/// `Result` is a convenient wrapper around the [`core::result::Result`] type, using the [`Error`]
/// enum defined in this crate as the error type.
pub type Result<T> = core::result::Result<T, Error>;

/// Enumeration of possible errors in the `codec_sv2` module.
///
/// This enum represents various errors that can occur within the `codec_sv2` module, including
/// errors from related crates like [`binary_sv2`], [`framing_sv2`], and `noise_sv2`.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// AEAD (`snow`) error in the Noise protocol.
    #[cfg(feature = "noise_sv2")]
    AeadError(AeadError),

    /// Binary Sv2 data format error.
    BinarySv2Error(binary_sv2::Error),

    /// Framing Sv2 error.
    FramingSv2Error(framing_sv2::Error),

    /// Incomplete frame, carrying the number of bytes the decoder will accept on the next read.
    ///
    /// This is the length of the slice the decoder's `writable` returns, capped at one chunk, and
    /// not the number of bytes left in the frame: a frame longer than a chunk is completed over
    /// several rounds.
    MissingBytes(usize),

    /// Sv2 Noise protocol error.
    #[cfg(feature = "noise_sv2")]
    NoiseSv2Error(NoiseError),

    /// The decoder buffer held a complete frame followed by the given number of surplus bytes.
    ///
    /// The buffered data, including that complete frame, has already been discarded.
    UnexpectedTrailingBytes(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            #[cfg(feature = "noise_sv2")]
            AeadError(e) => write!(f, "Aead Error: `{e:?}`"),
            BinarySv2Error(e) => write!(f, "Binary Sv2 Error: `{e:?}`"),
            FramingSv2Error(e) => write!(f, "Framing Sv2 Error: `{e:?}`"),
            MissingBytes(u) => write!(f, "Missing `{u}` bytes to fill the decoder read window"),
            #[cfg(feature = "noise_sv2")]
            NoiseSv2Error(e) => match e {
                NoiseError::InvalidCertificate(msg) => {
                    write!(f, "Invalid Certificate: {}", msg)
                }
                other => {
                    write!(f, "Noise SV2 Error: {:?}", other)
                }
            },
            UnexpectedTrailingBytes(u) => {
                write!(
                    f,
                    "Buffer held `{u}` bytes beyond the end of the frame; buffered data discarded"
                )
            }
        }
    }
}

#[cfg(feature = "noise_sv2")]
impl From<AeadError> for Error {
    fn from(e: AeadError) -> Self {
        Error::AeadError(e)
    }
}

impl From<binary_sv2::Error> for Error {
    fn from(e: binary_sv2::Error) -> Self {
        Error::BinarySv2Error(e)
    }
}

impl From<framing_sv2::Error> for Error {
    fn from(e: framing_sv2::Error) -> Self {
        Error::FramingSv2Error(e)
    }
}

#[cfg(feature = "noise_sv2")]
impl From<NoiseError> for Error {
    fn from(e: NoiseError) -> Self {
        Error::NoiseSv2Error(e)
    }
}
