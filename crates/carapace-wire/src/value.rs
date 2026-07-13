//! Deterministic-CBOR value model, canonical encoder, and strict decoder for
//! the restricted profile of Appendix B.1. This mirrors `cbor_vectors.py`'s
//! `enc`/`enc_uint` exactly on the encode side, and rejects every
//! non-canonical form on the decode side.

use crate::Error;

/// A map key: an unsigned integer `< 24` (single-byte encoding) or a byte
/// string (version-vector keys). These are the only key forms the profile
/// permits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Key {
    /// Unsigned integer key, restricted to `< 24`.
    Uint(u64),
    /// Byte-string key (used only by version vectors, keyed by device pubkey).
    Bytes(Vec<u8>),
}

impl Key {
    fn encoded(&self) -> Vec<u8> {
        match self {
            Key::Uint(n) => enc_uint(*n, 0),
            Key::Bytes(b) => {
                let mut out = enc_uint(b.len() as u64, 2);
                out.extend_from_slice(b);
                out
            }
        }
    }
}

/// A decoded / to-be-encoded CBOR value under the restricted profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// Major type 0, unsigned integer, shortest form.
    Uint(u64),
    /// Major type 2, byte string.
    Bytes(Vec<u8>),
    /// Major type 3, UTF-8 text string.
    Text(String),
    /// Major type 4, definite-length array.
    Array(Vec<Value>),
    /// Major type 5, definite-length map.
    Map(Map),
    /// Simple value `false`/`true`.
    Bool(bool),
    /// Simple value `null`.
    Null,
}

/// A CBOR map. Entries are stored in insertion (or decoded) order; the encoder
/// sorts bytewise-lexicographically on the encoded key. On decode, key order
/// is validated to be strictly increasing (which also rejects duplicates).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Map {
    entries: Vec<(Key, Value)>,
}

impl Map {
    /// A new empty map.
    pub fn new() -> Self {
        Map { entries: Vec::new() }
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the map has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Read-only view of the entries.
    pub fn entries(&self) -> &[(Key, Value)] {
        &self.entries
    }

    /// Consume the map into its raw entries (decoded / insertion order).
    pub fn into_entries(self) -> Vec<(Key, Value)> {
        self.entries
    }

    /// Push a raw key/value entry.
    pub fn push(&mut self, key: Key, val: Value) {
        self.entries.push((key, val));
    }

    /// Insert an unsigned-int-keyed value.
    pub fn u(&mut self, key: u64, val: Value) {
        self.entries.push((Key::Uint(key), val));
    }

    /// Remove and return the value for an unsigned-int key, if present.
    pub fn remove(&mut self, key: u64) -> Option<Value> {
        if let Some(i) = self.entries.iter().position(|(k, _)| *k == Key::Uint(key)) {
            Some(self.entries.remove(i).1)
        } else {
            None
        }
    }

    /// Remove a required unsigned-int-keyed value or error.
    pub fn take(&mut self, key: u64) -> Result<Value, Error> {
        self.remove(key).ok_or(Error::MissingField(key))
    }

    /// After all known keys are consumed, error if any entry remains
    /// (unknown-key rejection for a known message type).
    pub fn finish(self) -> Result<(), Error> {
        match self.entries.first() {
            None => Ok(()),
            Some((Key::Uint(k), _)) => Err(Error::UnknownKey(*k)),
            Some((Key::Bytes(_), _)) => Err(Error::UnknownByteKey),
        }
    }
}

impl Value {
    /// Consume as an unsigned integer.
    pub fn into_uint(self) -> Result<u64, Error> {
        match self {
            Value::Uint(n) => Ok(n),
            _ => Err(Error::TypeMismatch),
        }
    }

    /// Consume as a byte string.
    pub fn into_bytes(self) -> Result<Vec<u8>, Error> {
        match self {
            Value::Bytes(b) => Ok(b),
            _ => Err(Error::TypeMismatch),
        }
    }

    /// Consume as a fixed-length byte array.
    pub fn into_array_n<const N: usize>(self) -> Result<[u8; N], Error> {
        let b = self.into_bytes()?;
        b.try_into().map_err(|_| Error::WrongLength)
    }

    /// Consume as a text string.
    pub fn into_text(self) -> Result<String, Error> {
        match self {
            Value::Text(s) => Ok(s),
            _ => Err(Error::TypeMismatch),
        }
    }

    /// Consume as `text / null`.
    pub fn into_opt_text(self) -> Result<Option<String>, Error> {
        match self {
            Value::Text(s) => Ok(Some(s)),
            Value::Null => Ok(None),
            _ => Err(Error::TypeMismatch),
        }
    }

    /// Consume as a bool.
    pub fn into_bool(self) -> Result<bool, Error> {
        match self {
            Value::Bool(b) => Ok(b),
            _ => Err(Error::TypeMismatch),
        }
    }

    /// Consume as an array.
    pub fn into_list(self) -> Result<Vec<Value>, Error> {
        match self {
            Value::Array(v) => Ok(v),
            _ => Err(Error::TypeMismatch),
        }
    }

    /// Consume as a map.
    pub fn into_map(self) -> Result<Map, Error> {
        match self {
            Value::Map(m) => Ok(m),
            _ => Err(Error::TypeMismatch),
        }
    }
}

// ---------------- encoder (mirrors cbor_vectors.py enc/enc_uint) ----------

/// Encode an unsigned integer under `major`, shortest form.
pub fn enc_uint(n: u64, major: u8) -> Vec<u8> {
    let m = major << 5;
    if n < 24 {
        vec![m | (n as u8)]
    } else if n < 0x100 {
        let mut v = vec![m | 24];
        v.extend_from_slice(&(n as u8).to_be_bytes());
        v
    } else if n < 0x1_0000 {
        let mut v = vec![m | 25];
        v.extend_from_slice(&(n as u16).to_be_bytes());
        v
    } else if n < 0x1_0000_0000 {
        let mut v = vec![m | 26];
        v.extend_from_slice(&(n as u32).to_be_bytes());
        v
    } else {
        let mut v = vec![m | 27];
        v.extend_from_slice(&n.to_be_bytes());
        v
    }
}

/// Canonically encode a value under the restricted deterministic profile.
pub fn encode(v: &Value) -> Vec<u8> {
    match v {
        Value::Bool(b) => vec![if *b { 0xf5 } else { 0xf4 }],
        Value::Null => vec![0xf6],
        Value::Uint(n) => enc_uint(*n, 0),
        Value::Bytes(b) => {
            let mut out = enc_uint(b.len() as u64, 2);
            out.extend_from_slice(b);
            out
        }
        Value::Text(s) => {
            let b = s.as_bytes();
            let mut out = enc_uint(b.len() as u64, 3);
            out.extend_from_slice(b);
            out
        }
        Value::Array(items) => {
            let mut out = enc_uint(items.len() as u64, 4);
            for it in items {
                out.extend(encode(it));
            }
            out
        }
        Value::Map(m) => {
            let mut items: Vec<(Vec<u8>, Vec<u8>)> = m
                .entries
                .iter()
                .map(|(k, val)| (k.encoded(), encode(val)))
                .collect();
            items.sort_by(|a, b| a.0.cmp(&b.0));
            let mut out = enc_uint(items.len() as u64, 5);
            for (k, val) in items {
                out.extend(k);
                out.extend(val);
            }
            out
        }
    }
}

// ---------------- strict decoder ----------------------------------------

/// Maximum nesting depth for arrays/maps. The message and document schemas
/// nest at most ~8 levels; a cap of 32 is ample headroom while bounding
/// decoder recursion far below any thread stack limit (B.9: must error, not
/// panic/abort on adversarial input).
const MAX_DEPTH: usize = 32;

struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Decoder { buf, pos: 0 }
    }

    fn byte(&mut self) -> Result<u8, Error> {
        let b = *self.buf.get(self.pos).ok_or(Error::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        let s = self.buf.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    /// Read the argument for a head byte with additional-info `ai`, enforcing
    /// shortest form. Used for uint values and for string/array/map lengths.
    fn argument(&mut self, ai: u8) -> Result<u64, Error> {
        match ai {
            0..=23 => Ok(ai as u64),
            24 => {
                let v = self.byte()? as u64;
                if v < 24 {
                    return Err(Error::NonCanonicalInt);
                }
                Ok(v)
            }
            25 => {
                let b = self.take(2)?;
                let v = u16::from_be_bytes([b[0], b[1]]) as u64;
                if v < 0x100 {
                    return Err(Error::NonCanonicalInt);
                }
                Ok(v)
            }
            26 => {
                let b = self.take(4)?;
                let v = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
                if v < 0x1_0000 {
                    return Err(Error::NonCanonicalInt);
                }
                Ok(v)
            }
            27 => {
                let b = self.take(8)?;
                let v = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                if v < 0x1_0000_0000 {
                    return Err(Error::NonCanonicalInt);
                }
                Ok(v)
            }
            28..=30 => Err(Error::Reserved),
            _ => Err(Error::IndefiniteLength), // 31
        }
    }

    /// Read a length/count argument and reject any value that cannot possibly
    /// fit in the remaining buffer. This both guards the `u64 as usize`
    /// truncation on 32-bit targets (a value ≥ 2^32 can never index this
    /// ≤1 MiB buffer) and lets array/map counts (≥1 byte per element) fail
    /// fast rather than allocating.
    fn length(&mut self, ai: u8) -> Result<usize, Error> {
        let n = self.argument(ai)?;
        if n > self.buf.len() as u64 {
            return Err(Error::Truncated);
        }
        Ok(n as usize)
    }

    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::TooDeep);
        }
        let ib = self.byte()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        match major {
            0 => Ok(Value::Uint(self.argument(ai)?)),
            1 => Err(Error::NegativeInt),
            2 => {
                let len = self.length(ai)?;
                Ok(Value::Bytes(self.take(len)?.to_vec()))
            }
            3 => {
                let len = self.length(ai)?;
                let s = self.take(len)?;
                Ok(Value::Text(
                    core::str::from_utf8(s).map_err(|_| Error::InvalidUtf8)?.to_owned(),
                ))
            }
            4 => {
                let n = self.length(ai)?;
                let mut items = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    items.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let n = self.length(ai)?;
                let mut map = Map::new();
                let mut prev_key: Option<&[u8]> = None;
                for _ in 0..n {
                    let key_start = self.pos;
                    let key = self.key()?;
                    let key_bytes = &self.buf[key_start..self.pos];
                    if let Some(prev) = prev_key {
                        if key_bytes <= prev {
                            return Err(Error::UnsortedMapKeys);
                        }
                    }
                    prev_key = Some(key_bytes);
                    let val = self.value(depth + 1)?;
                    map.push(key, val);
                }
                Ok(Value::Map(map))
            }
            6 => Err(Error::Tag),
            _ => match ai {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                25..=27 => Err(Error::Float),
                _ => Err(Error::UnsupportedSimple),
            },
        }
    }

    fn key(&mut self) -> Result<Key, Error> {
        let ib = self.byte()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        match major {
            0 => {
                let n = self.argument(ai)?;
                if n >= 24 {
                    return Err(Error::InvalidMapKey);
                }
                Ok(Key::Uint(n))
            }
            2 => {
                let len = self.length(ai)?;
                Ok(Key::Bytes(self.take(len)?.to_vec()))
            }
            _ => Err(Error::InvalidMapKey),
        }
    }
}

/// Strictly decode one canonical value from the whole slice. Trailing bytes
/// are an error.
pub fn decode(buf: &[u8]) -> Result<Value, Error> {
    let mut d = Decoder::new(buf);
    let v = d.value(1)?;
    if d.pos != buf.len() {
        return Err(Error::TrailingBytes);
    }
    Ok(v)
}
