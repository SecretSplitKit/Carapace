//! carapace-wire: deterministic-CBOR codec, message registry, and signing
//! discipline for the Carapace protocol (Appendix B).
//!
//! - [`value`]: the restricted deterministic-CBOR value model, canonical
//!   encoder, and strict decoder (B.1).
//! - [`messages`]: framing (B.2), signing discipline (B.3), and the typed
//!   message/document registry (B.5, B.6).

pub mod messages;
pub mod value;

pub use messages::*;
pub use value::{decode, encode, Key, Map, Value};

use std::fmt;

/// Errors from encoding, decoding, or signature verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Input ended before a complete item was read.
    Truncated,
    /// Bytes remained after a complete top-level item.
    TrailingBytes,
    /// A negative integer (major type 1) was encountered; unsigned only.
    NegativeInt,
    /// An integer or length was not in shortest form.
    NonCanonicalInt,
    /// An indefinite-length item was encountered.
    IndefiniteLength,
    /// Nested arrays/maps exceeded the maximum decode depth.
    TooDeep,
    /// A reserved additional-info value (28-30) was encountered.
    Reserved,
    /// A tag (major type 6) was encountered.
    Tag,
    /// A floating-point value was encountered.
    Float,
    /// A simple value other than false/true/null was encountered.
    UnsupportedSimple,
    /// A text string was not valid UTF-8.
    InvalidUtf8,
    /// A map key was neither an unsigned int `< 24` nor a byte string.
    InvalidMapKey,
    /// Map keys were not strictly increasing on their encoded form (also
    /// catches duplicate keys).
    UnsortedMapKeys,
    /// A required field was missing.
    MissingField(u64),
    /// An unknown integer key was present in a known message type.
    UnknownKey(u64),
    /// An unknown byte-string key was present in a known message type.
    UnknownByteKey,
    /// A value had the wrong CBOR type for the target field.
    TypeMismatch,
    /// A byte string had the wrong length for a fixed-size field.
    WrongLength,
    /// A frame payload exceeded the 1 MiB cap.
    Oversized,
    /// A frame was not `[uint, map]`.
    BadFrame,
    /// A frame's type id did not match the expected message type.
    WrongType {
        /// The type id the decoder expected.
        expected: u64,
        /// The type id actually present.
        got: u64,
    },
    /// Signature verification failed or a public key was malformed.
    Signature,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated => write!(f, "input truncated"),
            Error::TrailingBytes => write!(f, "trailing bytes after item"),
            Error::NegativeInt => write!(f, "negative integer not permitted"),
            Error::NonCanonicalInt => write!(f, "integer or length not in shortest form"),
            Error::IndefiniteLength => write!(f, "indefinite-length item not permitted"),
            Error::TooDeep => write!(f, "nested item exceeds maximum decode depth"),
            Error::Reserved => write!(f, "reserved additional-info value"),
            Error::Tag => write!(f, "tags not permitted"),
            Error::Float => write!(f, "floating-point not permitted"),
            Error::UnsupportedSimple => write!(f, "unsupported simple value"),
            Error::InvalidUtf8 => write!(f, "invalid UTF-8 in text string"),
            Error::InvalidMapKey => write!(f, "invalid map key"),
            Error::UnsortedMapKeys => write!(f, "map keys not strictly increasing"),
            Error::MissingField(k) => write!(f, "missing required field {k}"),
            Error::UnknownKey(k) => write!(f, "unknown map key {k}"),
            Error::UnknownByteKey => write!(f, "unknown byte-string map key"),
            Error::TypeMismatch => write!(f, "value type mismatch"),
            Error::WrongLength => write!(f, "fixed-size byte string wrong length"),
            Error::Oversized => write!(f, "frame payload exceeds 1 MiB cap"),
            Error::BadFrame => write!(f, "frame is not [uint, map]"),
            Error::WrongType { expected, got } => {
                write!(f, "wrong message type: expected {expected}, got {got}")
            }
            Error::Signature => write!(f, "signature verification failed"),
        }
    }
}

impl std::error::Error for Error {}

impl From<ed25519_dalek::SignatureError> for Error {
    fn from(_: ed25519_dalek::SignatureError) -> Self {
        Error::Signature
    }
}
