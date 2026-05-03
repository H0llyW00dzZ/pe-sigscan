//! Wildcard byte pattern type and IDA-style hex parser.
//!
//! Two builder paths cover the common cases:
//!
//! - **Compile-time / static patterns.** Use the [`crate::pattern!`] macro
//!   defined in the crate root. Produces a `&'static [Option<u8>]` with no
//!   allocation. Preferred for hard-coded signatures known at build time.
//! - **Runtime / dynamic patterns.** Use [`Pattern::from_ida`]. Allocates a
//!   `Vec<Option<u8>>`. Preferred when the pattern is loaded from config,
//!   a dump file, an IDA copy/paste at runtime, or user input.
//!
//! The parser accepts the canonical IDA-style hex syntax — see the
//! `from_ida` doc for the exact grammar.

use alloc::vec::Vec;

use crate::error::{ParseErrorKind, ParsePatternError};

/// Wildcard-aware byte pattern as a slice of `Option<u8>`. `Some(b)` matches
/// the literal byte `b`; `None` matches any byte (the IDA-style `?` token).
///
/// Most callers will build patterns through the [`Pattern`] struct (for
/// runtime IDA-string parsing) or the [`crate::pattern!`] macro (for
/// compile-time constants). The raw slice type is exposed so the underlying
/// scan functions accept any source of pattern data without locking callers
/// into a particular wrapper.
pub type WildcardPattern<'a> = &'a [Option<u8>];

/// A wildcard byte pattern with parsed-from-string ergonomics.
///
/// Internally just a `Vec<Option<u8>>` for owned, runtime-built patterns.
/// For static / compile-time patterns prefer the [`crate::pattern!`] macro,
/// which produces a `&'static [Option<u8>]` with no allocation.
///
/// # Examples
///
/// ```
/// use pe_sigscan::Pattern;
///
/// let p = Pattern::from_ida("48 8B 05 ?? ?? ?? ?? 48 89 41 08").unwrap();
/// assert_eq!(p.len(), 11);
/// assert_eq!(p.as_slice()[0], Some(0x48));
/// assert_eq!(p.as_slice()[3], None);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    bytes: Vec<Option<u8>>,
}

impl Pattern {
    /// Construct a pattern from an existing `Vec<Option<u8>>`.
    ///
    /// Useful when the pattern is built programmatically (e.g. mutating an
    /// existing `Vec<Option<u8>>` to add wildcards before scanning).
    #[must_use]
    pub fn new(bytes: Vec<Option<u8>>) -> Self {
        Self { bytes }
    }

    /// Parse an IDA-style hex pattern string.
    ///
    /// Accepted token shapes (case-insensitive, separated by ASCII whitespace):
    ///
    /// - `XX` — two hex digits, matches the literal byte `0xXX`.
    /// - `?` or `??` — wildcard, matches any byte.
    ///
    /// # Examples
    ///
    /// ```
    /// use pe_sigscan::Pattern;
    /// let p = Pattern::from_ida("48 8B ?? 89").unwrap();
    /// assert_eq!(p.as_slice(), &[Some(0x48), Some(0x8B), None, Some(0x89)]);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`ParsePatternError`] if the input contains a token that is
    /// neither two hex digits nor `?` / `??`, or if a token mixes `?` with
    /// hex characters (`?A`, `1?`).
    pub fn from_ida(s: &str) -> Result<Self, ParsePatternError> {
        let mut bytes = Vec::new();
        for (idx, tok) in s.split_ascii_whitespace().enumerate() {
            let entry = match tok {
                "?" | "??" => None,
                _ => Some(parse_hex_byte(tok).map_err(|kind| ParsePatternError {
                    token_index: idx,
                    kind,
                })?),
            };
            bytes.push(entry);
        }
        if bytes.is_empty() {
            return Err(ParsePatternError {
                token_index: 0,
                kind: ParseErrorKind::Empty,
            });
        }
        Ok(Self { bytes })
    }

    /// View the pattern as a [`WildcardPattern`]. Use this when calling the
    /// scan functions: `find_in_text(base, pat.as_slice())`.
    #[must_use]
    pub fn as_slice(&self) -> WildcardPattern<'_> {
        &self.bytes
    }

    /// Number of byte slots in the pattern (literal + wildcard).
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// `true` if the pattern is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Parse a two-character hex byte. Returns the categorised error kind on
/// failure so [`Pattern::from_ida`] can attach the token index.
fn parse_hex_byte(tok: &str) -> Result<u8, ParseErrorKind> {
    let bytes = tok.as_bytes();
    if bytes.len() != 2 {
        return Err(ParseErrorKind::InvalidLength);
    }
    let hi = hex_digit(bytes[0]).ok_or(ParseErrorKind::InvalidHexDigit)?;
    let lo = hex_digit(bytes[1]).ok_or(ParseErrorKind::InvalidHexDigit)?;
    Ok((hi << 4) | lo)
}

/// Convert a single ASCII hex digit byte (`0-9`, `a-f`, `A-F`) to its
/// numeric value (`0..=15`). Returns `None` for any non-hex byte.
fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let p = Pattern::from_ida("48 8B 05").unwrap();
        assert_eq!(p.as_slice(), &[Some(0x48), Some(0x8B), Some(0x05)]);
    }

    #[test]
    fn parse_with_wildcards() {
        let p = Pattern::from_ida("48 ?? 05 ??").unwrap();
        assert_eq!(p.as_slice(), &[Some(0x48), None, Some(0x05), None]);
    }

    #[test]
    fn parse_single_question_wildcard() {
        let p = Pattern::from_ida("48 ? 05").unwrap();
        assert_eq!(p.as_slice(), &[Some(0x48), None, Some(0x05)]);
    }

    #[test]
    fn parse_case_insensitive() {
        let upper = Pattern::from_ida("AB CD EF").unwrap();
        let lower = Pattern::from_ida("ab cd ef").unwrap();
        let mixed = Pattern::from_ida("aB Cd eF").unwrap();
        assert_eq!(upper.as_slice(), lower.as_slice());
        assert_eq!(lower.as_slice(), mixed.as_slice());
    }

    #[test]
    fn parse_extra_whitespace_ok() {
        let p = Pattern::from_ida("  48\t8B\n??\r\n05  ").unwrap();
        assert_eq!(p.as_slice(), &[Some(0x48), Some(0x8B), None, Some(0x05)]);
    }

    #[test]
    fn parse_empty_errors() {
        let err = Pattern::from_ida("").unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::Empty);
    }

    #[test]
    fn parse_invalid_hex_errors() {
        // Both nibbles invalid — exercises the high-nibble `?` propagation
        // in `parse_hex_byte` (`hex_digit(bytes[0])` returns None first).
        let err = Pattern::from_ida("48 ZZ 05").unwrap_err();
        assert_eq!(err.token_index, 1);
        assert_eq!(err.kind, ParseErrorKind::InvalidHexDigit);
    }

    #[test]
    fn parse_invalid_low_nibble_only() {
        // High nibble VALID (`1`), low nibble INVALID (`Z`). Exercises the
        // low-nibble `?` propagation in `parse_hex_byte` — the high-nibble
        // path succeeded, then `hex_digit(bytes[1])` returns None and the
        // error propagates. Without this test, the low-nibble `?` line is
        // unreachable by any other input shape.
        let err = Pattern::from_ida("48 1Z 05").unwrap_err();
        assert_eq!(err.token_index, 1);
        assert_eq!(err.kind, ParseErrorKind::InvalidHexDigit);
    }

    #[test]
    fn parse_invalid_length_errors() {
        let err = Pattern::from_ida("48 8 05").unwrap_err();
        assert_eq!(err.token_index, 1);
        assert_eq!(err.kind, ParseErrorKind::InvalidLength);
    }

    #[test]
    fn pattern_new_from_vec() {
        let p = Pattern::new(alloc::vec![Some(0x48), None, Some(0x89)]);
        assert_eq!(p.len(), 3);
        assert_eq!(p.as_slice()[1], None);
    }

    #[test]
    fn pattern_is_empty() {
        let p = Pattern::new(alloc::vec![]);
        assert!(p.is_empty());
        assert_eq!(p.len(), 0);
    }
}
