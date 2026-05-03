//! Error types returned by IDA-style pattern parsing.
//!
//! See [`crate::Pattern::from_ida`] for the producer; [`ParsePatternError`]
//! is the only error this crate exposes.

/// Error returned by [`crate::Pattern::from_ida`] when the input string
/// contains an invalid token.
///
/// The error captures both the offending token's index and a categorised
/// reason ([`ParseErrorKind`]) so callers can produce a precise diagnostic
/// without re-parsing the input themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsePatternError {
    /// Zero-based index of the offending whitespace-separated token.
    pub token_index: usize,
    /// What was wrong with the token.
    pub kind: ParseErrorKind,
}

/// Categories of [`ParsePatternError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// The pattern string contained no tokens.
    Empty,
    /// Token was not exactly two hex digits or `?` / `??`.
    InvalidLength,
    /// Token had two characters but at least one was a non-hex digit (and
    /// it wasn't a `??` wildcard).
    InvalidHexDigit,
}

impl core::fmt::Display for ParsePatternError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.kind {
            ParseErrorKind::Empty => write!(f, "pattern string contained no tokens"),
            ParseErrorKind::InvalidLength => {
                write!(
                    f,
                    "token #{} must be two hex digits or `?` / `??`",
                    self.token_index
                )
            }
            ParseErrorKind::InvalidHexDigit => {
                write!(f, "token #{} contains a non-hex digit", self.token_index)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParsePatternError {}
