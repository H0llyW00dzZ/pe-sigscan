//! # pe-sigscan
//!
//! Fast in-process byte-pattern ("signature") scanning over the executable
//! sections of a loaded PE (Portable Executable) module on Windows.
//!
//! This crate is a building block for game mods, hookers, debuggers, and any
//! other in-process tool that needs to locate non-exported, non-vtable-
//! accessible code by its byte signature. It mirrors the workflow common
//! across the reverse-engineering ecosystem — derive a pattern from a
//! disassembler (IDA, Ghidra, Binary Ninja, Cutter), then scan the live
//! process's mapped image for it at runtime.
//!
//! ## Quick start
//!
//! ```no_run
//! use pe_sigscan::{find_in_text, Pattern};
//!
//! // Get a module base via your preferred means (GetModuleHandleW,
//! // PEB walk, etc.). For demonstration we assume a known base.
//! # let module_base = 0usize;
//!
//! // Build a pattern from an IDA-style hex string. `?` and `??` are
//! // wildcards; whitespace between bytes is ignored.
//! let pat = Pattern::from_ida("48 8B 05 ?? ?? ?? ?? 48 89 41 08").unwrap();
//!
//! if let Some(addr) = find_in_text(module_base, pat.as_slice()) {
//!     println!("matched at {addr:#x}");
//! }
//! ```
//!
//! Or with the `pattern!` macro (no allocation, fully `const`-eligible):
//!
//! ```
//! use pe_sigscan::pattern;
//!
//! const SIG: &[Option<u8>] = pattern![0x48, 0x8B, _, _, 0x48, 0x89];
//! assert_eq!(SIG.len(), 6);
//! assert_eq!(SIG[0], Some(0x48));
//! assert_eq!(SIG[2], None);
//! ```
//!
//! ## Two scanning modes
//!
//! - [`find_in_text`] / [`count_in_text`] / [`iter_in_text`] — walk only
//!   the section literally named `.text`. The simplest case, suitable for
//!   MSVC-built DLLs that put everything in one code section.
//! - [`find_in_exec_sections`] / [`count_in_exec_sections`] /
//!   [`iter_in_exec_sections`] — walk every section whose
//!   `IMAGE_SCN_MEM_EXECUTE` characteristic is set. Required when the
//!   function you're scanning for might live in a companion section like
//!   `.text$mn`, `.textbss`, a jump-table arena, or any of the
//!   optimized-layout code sections that some compilers and linkers emit.
//!
//! Both modes have [`find_in_slice`] / [`count_in_slice`] / [`iter_in_slice`]
//! companions that work on a `&[u8]` instead of a loaded PE — useful for
//! offline analysis, unit testing, and scanning extracted bytes.
//!
//! ## Resolving rel32 displacements
//!
//! Real signature workflows almost always end with "match the
//! instruction, then follow its `rel32` displacement to the actual target
//! address". The [`resolve_rel32`] / [`resolve_rel32_at`] helpers package
//! that arithmetic so callers don't reinvent the off-by-one-prone
//! `next_ip + disp32` calculation:
//!
//! ```no_run
//! use pe_sigscan::{find_in_text, pattern, resolve_rel32_at};
//! # let module_base = 0usize;
//!
//! // mov rax, [rip+disp32]: 48 8B 05 ?? ?? ?? ?? (7 bytes total).
//! const SIG: &[Option<u8>] = pattern![0x48, 0x8B, 0x05, _, _, _, _];
//! if let Some(addr) = find_in_text(module_base, SIG) {
//!     let target = unsafe { resolve_rel32_at(addr, 3, 7) };
//!     println!("global at {target:#x}");
//! }
//! ```
//!
//! ## Why direct memory reads?
//!
//! The `.text` section of a loaded DLL is page-aligned, RX-protected, and
//! stays committed for the lifetime of the module. There is no TOCTOU
//! concern; bytes don't change between reads. A typical scan walks tens of
//! megabytes of bytes — routing every probe through `ReadProcessMemory`
//! would cost tens of millions of syscalls (minutes of wall time). This
//! crate reads directly via raw pointer dereference, bounded to PE-declared
//! section ranges.
//!
//! ## Safety
//!
//! Public functions take a `module_base: usize` you must obtain from the OS
//! (e.g. `GetModuleHandleW`). The implementation parses the PE headers at
//! that base before any other access, so a non-PE pointer is rejected
//! cleanly. Inside the validated section ranges, the unsafe pointer reads
//! are bounded by the `VirtualSize` field from the section header — outside
//! the loader handing us a malformed PE (which the loader itself would have
//! rejected), there is no path to an out-of-bounds read.
//!
//! The slice variants are safe by Rust's slice invariants and need no
//! further trust from the caller.
//!
//! ## Platform
//!
//! Windows / PE only.
//!
//! The crate compiles on every platform — the parsing is pure compute —
//! but the in-process function signatures assume a `module_base` that came
//! from the Windows loader. On non-Windows targets, the slice variants
//! still work for analysing PE bytes you have mapped manually.
//!
//! ## License
//!
//! MIT OR Apache-2.0.

#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![warn(unreachable_pub)]
#![allow(unsafe_op_in_unsafe_fn)]

extern crate alloc;

mod error;
mod fastscan;
mod instr;
mod pattern;
mod pe;
mod scan;

pub use crate::error::{ParseErrorKind, ParsePatternError};
pub use crate::instr::{read_rel32, resolve_rel32, resolve_rel32_at};
pub use crate::pattern::{Pattern, WildcardPattern};
pub use crate::scan::{
    count_in_exec_sections, count_in_slice, count_in_text, find_in_exec_sections, find_in_slice,
    find_in_text, iter_in_exec_sections, iter_in_slice, iter_in_text, Matches, SliceMatches,
};

// Section-targeted scanners (feature `section-info`).
//
// `find_in_section` / `count_in_section` / `iter_in_section` live in
// `scan.rs` alongside the always-available scanners; they're the
// same shape as `find_in_text` etc. but take a section name as a
// parameter, letting callers scan inside `.rdata`, `.pdata`,
// `.text$mn`, etc. Internally they delegate to `crate::pe::find_section`.
//
// The feature also re-exports the section-lookup helpers from
// `crate::pe` so that advanced users can implement their own
// section-specific logic if needed.
#[cfg(feature = "section-info")]
pub use crate::scan::{count_in_section, find_in_section, iter_in_section};

// `module_size` is a standalone reader for
// `IMAGE_OPTIONAL_HEADER.SizeOfImage` — useful for cross-module
// rel32 disambiguation (pairs naturally with the always-available
// `resolve_rel32*` helpers). It is exported unconditionally.
pub use crate::pe::module_size;

// ---------------------------------------------------------------------------
// pattern! macro
// ---------------------------------------------------------------------------
//
// Macros must be defined at the crate root (or re-exported with
// `#[macro_export]`) to be reachable as `pe_sigscan::pattern!`. We keep the
// definition here rather than in a `macros` submodule so the public macro
// path is the natural `crate::pattern!`.

/// Build a `&'static [Option<u8>; N]` at compile time from a list of byte
/// literals and `_` wildcards.
///
/// # Examples
///
/// ```
/// use pe_sigscan::pattern;
///
/// // `_` is the wildcard token. Use byte literals (0xNN) for fixed bytes.
/// const SIG: &[Option<u8>] = pattern![0x48, 0x8B, _, _, 0x48, 0x89];
/// assert_eq!(SIG, &[Some(0x48), Some(0x8B), None, None, Some(0x48), Some(0x89)]);
/// ```
///
/// This is the zero-cost / no-allocation alternative to
/// [`Pattern::from_ida`]. Use it when the pattern is known at compile time
/// (the common case for hard-coded signatures); use `Pattern::from_ida`
/// when the pattern is loaded from config, a dump file, or user input at
/// runtime.
#[macro_export]
macro_rules! pattern {
    [ $( $tok:tt ),* $(,)? ] => {
        &[ $( $crate::__pattern_token!($tok) ),* ]
    };
}

/// Helper for [`pattern!`] — converts a single token into `Some(byte)` or
/// `None`. Hidden from the public surface; users should not call this
/// directly.
#[doc(hidden)]
#[macro_export]
macro_rules! __pattern_token {
    (_) => {
        ::core::option::Option::<u8>::None
    };
    ($byte:literal) => {
        ::core::option::Option::<u8>::Some($byte)
    };
}

// ---------------------------------------------------------------------------
// Crate-level integration tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- pattern! macro --------------------------------------------------

    #[test]
    fn pattern_macro_no_wildcards() {
        const SIG: &[Option<u8>] = pattern![0x48, 0x8B, 0x05];
        assert_eq!(SIG, &[Some(0x48), Some(0x8B), Some(0x05)]);
    }

    #[test]
    fn pattern_macro_with_wildcards() {
        const SIG: &[Option<u8>] = pattern![0x48, _, 0x05, _, _];
        assert_eq!(SIG, &[Some(0x48), None, Some(0x05), None, None]);
    }

    #[test]
    fn pattern_macro_trailing_comma() {
        // `$(,)?` — trailing comma should compile.
        const SIG: &[Option<u8>] = pattern![0x48, 0x8B,];
        assert_eq!(SIG, &[Some(0x48), Some(0x8B)]);
    }

    #[test]
    fn pattern_macro_empty() {
        // Zero-token form should compile to an empty slice.
        const SIG: &[Option<u8>] = pattern![];
        assert!(SIG.is_empty());
    }

    #[test]
    fn pattern_macro_single_byte() {
        const SIG: &[Option<u8>] = pattern![0xCC];
        assert_eq!(SIG, &[Some(0xCC)]);
    }

    #[test]
    fn pattern_macro_single_wildcard() {
        const SIG: &[Option<u8>] = pattern![_];
        assert_eq!(SIG, &[None]);
    }

    // -- error display ---------------------------------------------------

    #[test]
    fn error_display_empty() {
        let e = ParsePatternError {
            token_index: 0,
            kind: ParseErrorKind::Empty,
        };
        let s = alloc::format!("{e}");
        assert!(s.contains("no tokens"), "got: {s}");
    }

    #[test]
    fn error_display_invalid_length() {
        let e = ParsePatternError {
            token_index: 3,
            kind: ParseErrorKind::InvalidLength,
        };
        let s = alloc::format!("{e}");
        assert!(s.contains("token #3"), "got: {s}");
        assert!(s.contains("two hex digits"), "got: {s}");
    }

    #[test]
    fn error_display_invalid_hex_digit() {
        let e = ParsePatternError {
            token_index: 1,
            kind: ParseErrorKind::InvalidHexDigit,
        };
        let s = alloc::format!("{e}");
        assert!(s.contains("token #1"), "got: {s}");
        assert!(s.contains("non-hex"), "got: {s}");
    }

    #[test]
    fn error_is_copy_and_clone() {
        let e = ParsePatternError {
            token_index: 0,
            kind: ParseErrorKind::Empty,
        };
        let copied = e;
        let cloned = e.clone();
        assert_eq!(copied, e);
        assert_eq!(cloned, e);
    }

    #[test]
    fn error_kind_equality() {
        // Touch the `PartialEq` derive on every variant so coverage tools
        // see the discriminant comparisons exercised.
        assert_eq!(ParseErrorKind::Empty, ParseErrorKind::Empty);
        assert_eq!(ParseErrorKind::InvalidLength, ParseErrorKind::InvalidLength);
        assert_eq!(
            ParseErrorKind::InvalidHexDigit,
            ParseErrorKind::InvalidHexDigit
        );
        assert_ne!(ParseErrorKind::Empty, ParseErrorKind::InvalidLength);
        assert_ne!(ParseErrorKind::Empty, ParseErrorKind::InvalidHexDigit);
        assert_ne!(
            ParseErrorKind::InvalidLength,
            ParseErrorKind::InvalidHexDigit
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn error_implements_std_error() {
        // Existence proof: this only compiles if the trait impl exists.
        fn assert_error<E: std::error::Error>(_: &E) {}
        let e = ParsePatternError {
            token_index: 0,
            kind: ParseErrorKind::Empty,
        };
        assert_error(&e);
    }

    // -- Pattern API smoke -----------------------------------------------

    #[test]
    fn pattern_clone_and_eq() {
        let p1 = Pattern::from_ida("48 8B ?? 89").unwrap();
        let p2 = p1.clone();
        assert_eq!(p1, p2);
    }

    #[test]
    fn pattern_debug() {
        // Touch the `Debug` derive so coverage records it.
        let p = Pattern::from_ida("48").unwrap();
        let s = alloc::format!("{p:?}");
        assert!(s.contains("Pattern"), "got: {s}");
    }

    #[test]
    fn pattern_as_slice_round_trip() {
        let p = Pattern::from_ida("48 ??").unwrap();
        let s = p.as_slice();
        assert_eq!(s.len(), 2);
        assert_eq!(s[0], Some(0x48));
        assert_eq!(s[1], None);
    }
}
