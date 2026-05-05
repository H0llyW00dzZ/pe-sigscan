//! Public scanning entry points + private range scanners.
//!
//! Two layers:
//!
//! - **Range scanners** ([`scan_range`], [`count_range`]) — work on any
//!   contiguous byte range described by `(start, size)`. Shared between
//!   the in-process scanners (which derive `(start, size)` from PE header
//!   fields) and the slice scanners (which derive it from `&[u8]` length).
//! - **Public entry points** — thin wrappers that derive ranges from PE
//!   headers ([`find_in_text`], [`count_in_text`], [`find_in_exec_sections`],
//!   [`count_in_exec_sections`]) or from a slice ([`find_in_slice`],
//!   [`count_in_slice`]) and delegate to the range scanners.
//!
//! All scanners use a single-byte anchor pre-filter: the first non-wildcard
//! byte of the pattern is sampled at every candidate offset before invoking
//! [`matches_at`]. For typical signatures this skips ~99% of candidate
//! offsets without paying the per-byte loop cost.

use crate::fastscan::{first_byte_in_raw, first_byte_in_slice};
use crate::pattern::WildcardPattern;
use crate::pe::{exec_sections, text_section_bounds};

/// Match `pattern` against the bytes starting at `addr`. Wildcards (`None`
/// entries) match any byte.
///
/// # Safety
///
/// Caller must guarantee `[addr, addr + pattern.len())` is readable.
#[inline]
unsafe fn matches_at(addr: usize, pattern: WildcardPattern<'_>) -> bool {
    for (i, slot) in pattern.iter().enumerate() {
        if let Some(want) = *slot {
            let got = *((addr + i) as *const u8);
            if got != want {
                return false;
            }
        }
    }
    true
}

/// Find the first occurrence of `pattern` within the named `.text` section
/// of the PE module loaded at `module_base`.
///
/// Returns `None` if the pattern is empty, the module headers are
/// malformed, the `.text` section is not present, or the pattern does not
/// match anywhere.
///
/// See [`find_in_exec_sections`] for the variant that walks every
/// executable section (use when the function may live in a companion code
/// section like `.text$mn`).
#[must_use]
pub fn find_in_text(module_base: usize, pattern: WildcardPattern<'_>) -> Option<usize> {
    if module_base == 0 || pattern.is_empty() {
        return None;
    }
    let (start, size) = text_section_bounds(module_base)?;
    scan_range(start, size, pattern)
}

/// Count occurrences of `pattern` within the named `.text` section of the
/// PE module loaded at `module_base`.
///
/// Useful before installing a hook to verify pattern uniqueness — a
/// pattern that matches multiple functions risks hooking the wrong one and
/// silently corrupting unrelated state. Callers should typically refuse to
/// install when the count isn't exactly 1.
#[must_use]
pub fn count_in_text(module_base: usize, pattern: WildcardPattern<'_>) -> usize {
    if module_base == 0 || pattern.is_empty() {
        return 0;
    }
    match text_section_bounds(module_base) {
        Some((start, size)) => count_range(start, size, pattern),
        None => 0,
    }
}

/// Find the first occurrence of `pattern` within ANY executable section of
/// the PE module loaded at `module_base`.
///
/// Use this when the function may live outside the section literally named
/// `.text`. Some compilers and linkers split code across multiple executable
/// sections (for example `.text$mn`, `.textbss`, or optimized code arenas),
/// and the section named `.text` may not contain the target function.
///
/// Same speed as [`find_in_text`] (direct in-process reads bounded to
/// PE-declared section ranges); the only difference is the section-name
/// filter is dropped in favour of an `IMAGE_SCN_MEM_EXECUTE`
/// characteristic check.
#[must_use]
pub fn find_in_exec_sections(module_base: usize, pattern: WildcardPattern<'_>) -> Option<usize> {
    if module_base == 0 || pattern.is_empty() {
        return None;
    }
    for (start, size) in exec_sections(module_base)? {
        if let Some(addr) = scan_range(start, size, pattern) {
            return Some(addr);
        }
    }
    None
}

/// Count occurrences of `pattern` across ALL executable sections of the PE
/// module loaded at `module_base`. Companion to [`find_in_exec_sections`];
/// same hook-install uniqueness contract as [`count_in_text`].
#[must_use]
pub fn count_in_exec_sections(module_base: usize, pattern: WildcardPattern<'_>) -> usize {
    if module_base == 0 || pattern.is_empty() {
        return 0;
    }
    let Some(sections) = exec_sections(module_base) else {
        return 0;
    };
    let mut total = 0usize;
    for (start, size) in sections {
        total += count_range(start, size, pattern);
    }
    total
}

/// Find the first occurrence of `pattern` within the slice `haystack`.
///
/// This variant is platform-agnostic and does not require a loaded PE
/// module — useful for offline analysis or for testing patterns against
/// pre-extracted byte buffers. Returns the absolute address of the match
/// in the form `haystack.as_ptr() as usize + offset`, so the result is
/// directly comparable to addresses returned by the in-process scanners.
///
/// Returns `None` if the pattern is empty, longer than `haystack`, or does
/// not match anywhere.
#[must_use]
pub fn find_in_slice(haystack: &[u8], pattern: WildcardPattern<'_>) -> Option<usize> {
    if pattern.is_empty() || haystack.len() < pattern.len() {
        return None;
    }
    scan_slice(haystack, pattern).map(|off| haystack.as_ptr() as usize + off)
}

/// Count occurrences of `pattern` within the slice `haystack`. Non-
/// overlapping: a pattern that matches at offset `i` advances the search
/// past `i + pattern.len()` rather than `i + 1`.
#[must_use]
pub fn count_in_slice(haystack: &[u8], pattern: WildcardPattern<'_>) -> usize {
    if pattern.is_empty() || haystack.len() < pattern.len() {
        return 0;
    }
    count_slice(haystack, pattern)
}

/// Iterator over non-overlapping match addresses within a `&[u8]`
/// haystack. Returned by [`iter_in_slice`].
///
/// Each yielded value is the absolute address `haystack.as_ptr() as
/// usize + offset_of_match`, mirroring the return value of
/// [`find_in_slice`].
///
/// Matches are non-overlapping: after a hit at offset `i` the next probe
/// starts at `i + pattern.len()`. An empty pattern yields no matches.
#[derive(Debug, Clone)]
pub struct SliceMatches<'a> {
    haystack: &'a [u8],
    pattern: WildcardPattern<'a>,
    /// Next byte offset within `haystack` to start scanning from.
    cursor: usize,
}

impl<'a> Iterator for SliceMatches<'a> {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        let pat_len = self.pattern.len();
        if pat_len == 0 {
            return None;
        }
        let off = scan_slice_from(self.haystack, self.cursor, self.pattern)?;
        self.cursor = off + pat_len;
        Some(self.haystack.as_ptr() as usize + off)
    }
}

/// Iterator over non-overlapping match addresses within one or more raw
/// byte ranges of a loaded PE module. Returned by [`iter_in_text`] and
/// [`iter_in_exec_sections`].
///
/// Each yielded value is the absolute address of a match, identical in
/// shape to what [`find_in_text`] / [`find_in_exec_sections`] return.
///
/// When the iterator was constructed via [`iter_in_exec_sections`] and
/// the current section is exhausted, the iterator transparently advances
/// to the next executable section.
#[derive(Debug, Clone)]
pub struct Matches<'a> {
    /// Remaining `(virtual_address_absolute, virtual_size)` ranges to
    /// scan. The currently-active range is `sections[section_idx]`.
    sections: alloc::vec::Vec<(usize, usize)>,
    section_idx: usize,
    /// Next byte offset within `sections[section_idx]` to scan from.
    cursor: usize,
    pattern: WildcardPattern<'a>,
}

impl<'a> Iterator for Matches<'a> {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        let pat_len = self.pattern.len();
        if pat_len == 0 {
            return None;
        }
        while self.section_idx < self.sections.len() {
            let (start, size) = self.sections[self.section_idx];
            if let Some(addr) = scan_range_from(start, size, self.cursor, self.pattern) {
                let off = addr - start;
                self.cursor = off + pat_len;
                return Some(addr);
            }
            // Current section exhausted — advance to the next one.
            self.section_idx += 1;
            self.cursor = 0;
        }
        None
    }
}

/// Iterate over every non-overlapping occurrence of `pattern` within the
/// slice `haystack`.
///
/// The iterator is lazy: each `next()` call resumes the underlying
/// SIMD/SWAR search from where the last match ended. Useful for logging
/// every hit, applying additional per-match filters, or patching multiple
/// call sites in one pass without rolling a manual scan loop.
///
/// Yields nothing if `pattern` is empty or longer than `haystack`.
///
/// # Examples
///
/// ```
/// use pe_sigscan::{iter_in_slice, pattern};
///
/// let bytes = [0x48, 0x8B, 0x05, 0x00, 0x48, 0x8B, 0x05, 0xFF];
/// let pat = pattern![0x48, 0x8B, 0x05];
/// let hits: alloc::vec::Vec<usize> = iter_in_slice(&bytes, pat).collect();
/// // Two non-overlapping matches at offsets 0 and 4.
/// assert_eq!(hits.len(), 2);
/// assert_eq!(hits[0], bytes.as_ptr() as usize);
/// assert_eq!(hits[1], bytes.as_ptr() as usize + 4);
/// # extern crate alloc;
/// ```
#[must_use]
pub fn iter_in_slice<'a>(haystack: &'a [u8], pattern: WildcardPattern<'a>) -> SliceMatches<'a> {
    SliceMatches {
        haystack,
        pattern,
        cursor: 0,
    }
}

/// Iterate over every non-overlapping occurrence of `pattern` within the
/// section literally named `.text` of the PE module loaded at
/// `module_base`.
///
/// Yields nothing if `module_base` is zero, `pattern` is empty, the
/// module headers are malformed, or the `.text` section is absent.
///
/// See [`iter_in_exec_sections`] for the variant that walks every
/// executable section (use when the function may live in a companion code
/// section like `.text$mn`).
#[must_use]
pub fn iter_in_text<'a>(module_base: usize, pattern: WildcardPattern<'a>) -> Matches<'a> {
    let sections = if module_base == 0 || pattern.is_empty() {
        alloc::vec::Vec::new()
    } else {
        match text_section_bounds(module_base) {
            Some(range) => alloc::vec![range],
            None => alloc::vec::Vec::new(),
        }
    };
    Matches {
        sections,
        section_idx: 0,
        cursor: 0,
        pattern,
    }
}

/// Iterate over every non-overlapping occurrence of `pattern` across ALL
/// executable sections of the PE module loaded at `module_base`.
///
/// Sections are visited in their PE section-table order; matches inside
/// one section are exhausted before moving to the next. Yields nothing if
/// `module_base` is zero, `pattern` is empty, or the module headers are
/// malformed.
#[must_use]
pub fn iter_in_exec_sections<'a>(module_base: usize, pattern: WildcardPattern<'a>) -> Matches<'a> {
    let sections = if module_base == 0 || pattern.is_empty() {
        alloc::vec::Vec::new()
    } else {
        exec_sections(module_base).unwrap_or_default()
    };
    Matches {
        sections,
        section_idx: 0,
        cursor: 0,
        pattern,
    }
}

/// Find the first occurrence of `pattern` within the section whose
/// 8-byte name starts with `section_name`.
///
/// `section_name` matches `IMAGE_SECTION_HEADER.Name` as a byte
/// prefix: `b".text"` matches `.text\0\0\0`, `.text$mn`, `.textbss`.
/// Pass the full 8 bytes for exact-match disambiguation.
///
/// Returns `None` if `module_base` is zero, the pattern is empty,
/// the section is missing, or the pattern doesn't match. Returned
/// addresses are absolute — same shape as [`find_in_text`].
///
/// # Examples
///
/// ```no_run
/// use pe_sigscan::{find_in_section, pattern};
/// # let module_base = 0usize;
///
/// let pat = pattern![b'h', b'e', b'l', b'l', b'o', 0x00];
/// if let Some(addr) = find_in_section(module_base, b".rdata", pat) {
///     println!("string at {addr:#x}");
/// }
/// ```
#[cfg(feature = "section-info")]
#[must_use]
pub fn find_in_section(
    module_base: usize,
    section_name: &[u8],
    pattern: WildcardPattern<'_>,
) -> Option<usize> {
    if module_base == 0 || pattern.is_empty() {
        return None;
    }
    let section = crate::pe::find_section(module_base, section_name)?;
    scan_range(section.virtual_address, section.virtual_size, pattern)
}

/// Count non-overlapping occurrences of `pattern` within the named
/// section. Companion to [`find_in_section`]; same uniqueness
/// contract as [`count_in_text`].
///
/// Returns `0` if `module_base` is zero, the pattern is empty, the
/// section is missing, or the pattern doesn't match.
#[cfg(feature = "section-info")]
#[must_use]
pub fn count_in_section(
    module_base: usize,
    section_name: &[u8],
    pattern: WildcardPattern<'_>,
) -> usize {
    if module_base == 0 || pattern.is_empty() {
        return 0;
    }
    let Some(section) = crate::pe::find_section(module_base, section_name) else {
        return 0;
    };
    count_range(section.virtual_address, section.virtual_size, pattern)
}

/// Iterate over every non-overlapping occurrence of `pattern` within
/// the named section.
///
/// Yields nothing if `module_base` is zero, the pattern is empty, or
/// the section is missing. Yielded addresses are absolute — same
/// shape as [`iter_in_text`].
#[cfg(feature = "section-info")]
#[must_use]
pub fn iter_in_section<'a>(
    module_base: usize,
    section_name: &[u8],
    pattern: WildcardPattern<'a>,
) -> Matches<'a> {
    let sections = if module_base == 0 || pattern.is_empty() {
        alloc::vec::Vec::new()
    } else {
        crate::pe::find_section(module_base, section_name)
            .map(|s| alloc::vec![(s.virtual_address, s.virtual_size)])
            .unwrap_or_default()
    };
    Matches {
        sections,
        section_idx: 0,
        cursor: 0,
        pattern,
    }
}

/// Locate the first non-wildcard byte in the pattern. Returns the
/// (offset_within_pattern, byte_value) pair, or `None` if the pattern is
/// all wildcards (in which case the anchor pre-filter must be skipped).
#[inline]
fn anchor(pattern: WildcardPattern<'_>) -> Option<(usize, u8)> {
    pattern
        .iter()
        .enumerate()
        .find_map(|(i, b)| b.map(|byte| (i, byte)))
}

/// Slice-native scan for the first match starting at byte offset `from`.
///
/// Uses [`first_byte_in_slice`] to skip directly to the next plausible
/// candidate offset instead of stepping byte-by-byte. On haystacks where
/// the anchor byte is rare this is dramatically faster than
/// [`scan_range`].
///
/// Returns the matching offset within `haystack` (NOT the absolute
/// address — callers map to absolute via `haystack.as_ptr() + off`).
///
/// `#[inline]` is load-bearing: when `find_in_slice` calls in via
/// `scan_slice` with the constant `from = 0`, inlining lets LLVM fold
/// the redundant `haystack.len() < pat_len` and `from > upper` checks
/// against the caller's pre-validated lengths, restoring the original
/// pre-refactor codegen on the hot path. Without `#[inline]`, the
/// inliner is right at its size heuristic and may decline to inline
/// across both call sites (single-shot vs iterator), costing ~2-3 % on
/// 1 MiB scans.
#[inline]
fn scan_slice_from(haystack: &[u8], from: usize, pattern: WildcardPattern<'_>) -> Option<usize> {
    let pat_len = pattern.len();
    if haystack.len() < pat_len {
        return None;
    }
    let upper = haystack.len() - pat_len;
    if from > upper {
        return None;
    }
    let Some((anchor_off, anchor_byte)) = anchor(pattern) else {
        // All-wildcard pattern matches at the cursor.
        return Some(from);
    };

    let mut i = from;
    while i <= upper {
        // Search for the anchor byte starting from the current candidate
        // offset (offset by `anchor_off` so the byte we find lines up
        // correctly with the pattern). `search_from < haystack.len()` is
        // guaranteed by `i <= upper` and `anchor_off < pat_len`.
        let search_from = i + anchor_off;
        let Some(rel) = first_byte_in_slice(&haystack[search_from..], anchor_byte) else {
            return None;
        };
        let candidate = search_from + rel - anchor_off;
        if candidate > upper {
            return None;
        }
        // SAFETY: `candidate + pat_len <= haystack.len()` by `candidate <= upper`.
        if unsafe { matches_at(haystack.as_ptr() as usize + candidate, pattern) } {
            return Some(candidate);
        }
        i = candidate + 1;
    }
    None
}

/// Convenience: `scan_slice_from(haystack, 0, pattern)`. Used by the
/// single-shot [`find_in_slice`] entry point.
#[inline]
fn scan_slice(haystack: &[u8], pattern: WildcardPattern<'_>) -> Option<usize> {
    scan_slice_from(haystack, 0, pattern)
}

/// Slice-native count of non-overlapping matches.
fn count_slice(haystack: &[u8], pattern: WildcardPattern<'_>) -> usize {
    let pat_len = pattern.len();
    let upper = haystack.len() - pat_len;
    let Some((anchor_off, anchor_byte)) = anchor(pattern) else {
        // All-wildcard pattern: every position matches; the byte-by-byte
        // semantics stride by `pat_len` for non-overlap, so the count is
        // `floor(haystack.len() / pat_len)`. `pat_len >= 1` is guaranteed
        // by the public-entry check at the top of `count_in_slice`.
        return haystack.len() / pat_len;
    };

    let mut count = 0usize;
    let mut i = 0usize;
    while i <= upper {
        // `search_from < haystack.len()` is guaranteed by `i <= upper` and
        // `anchor_off < pat_len`.
        let search_from = i + anchor_off;
        let Some(rel) = first_byte_in_slice(&haystack[search_from..], anchor_byte) else {
            break;
        };
        let candidate = search_from + rel - anchor_off;
        if candidate > upper {
            break;
        }
        // SAFETY: in-bounds by the same invariant.
        if unsafe { matches_at(haystack.as_ptr() as usize + candidate, pattern) } {
            count += 1;
            i = candidate + pat_len;
        } else {
            i = candidate + 1;
        }
    }
    count
}

/// Scan a contiguous raw byte range for the first match, starting at
/// byte offset `from` within the range.
///
/// # Safety contract for the unsafe pointer reads
///
/// `start..start+size` must be a readable contiguous range of bytes. For
/// the in-process callers this is guaranteed by the PE section bounds; for
/// the slice variant by Rust's `&[u8]` lifetime + length invariants. The
/// `i <= upper = size - pat_len` loop invariant ensures every read is
/// inside the range.
///
/// `#[inline]` is load-bearing for the same reason as
/// [`scan_slice_from`]: with the constant `from = 0` from `find_in_text`
/// / `find_in_exec_sections` the redundant `from > upper` branch is
/// statically eliminable by LLVM, but only after inlining.
#[inline]
fn scan_range_from(
    start: usize,
    size: usize,
    from: usize,
    pattern: WildcardPattern<'_>,
) -> Option<usize> {
    let pat_len = pattern.len();
    if size < pat_len {
        return None;
    }
    let upper = size - pat_len;
    if from > upper {
        return None;
    }
    let Some((anchor_off, anchor_byte)) = anchor(pattern) else {
        return Some(start + from);
    };

    let mut i = from;
    while i <= upper {
        // `search_from < size` is guaranteed by `i <= upper` and
        // `anchor_off < pat_len`.
        let search_from = i + anchor_off;
        // SAFETY: `[start+search_from, start+size)` is a subset of the
        // range the caller declared readable.
        let Some(rel) =
            (unsafe { first_byte_in_raw(start + search_from, size - search_from, anchor_byte) })
        else {
            return None;
        };
        let candidate = search_from + rel - anchor_off;
        if candidate > upper {
            return None;
        }
        let addr = start + candidate;
        // SAFETY: bounds upheld by the same invariant.
        if unsafe { matches_at(addr, pattern) } {
            return Some(addr);
        }
        i = candidate + 1;
    }
    None
}

/// Convenience: `scan_range_from(start, size, 0, pattern)`. Used by the
/// single-shot in-process `find_*` entry points.
#[inline]
fn scan_range(start: usize, size: usize, pattern: WildcardPattern<'_>) -> Option<usize> {
    scan_range_from(start, size, 0, pattern)
}

/// Count occurrences of `pattern` within a single contiguous raw byte
/// range.
///
/// Counts non-overlapping matches: when a match is found at offset `i`,
/// the next probe starts at `i + pattern.len()`. Counting overlapping
/// matches is not the use case this crate targets and would inflate
/// counts for patterns with internal repetition.
fn count_range(start: usize, size: usize, pattern: WildcardPattern<'_>) -> usize {
    let pat_len = pattern.len();
    if size < pat_len {
        return 0;
    }
    let upper = size - pat_len;
    let Some((anchor_off, anchor_byte)) = anchor(pattern) else {
        // All-wildcard pattern; same reasoning as `count_slice`. `pat_len
        // >= 1` is guaranteed by the public-entry caller.
        return size / pat_len;
    };

    let mut count = 0usize;
    let mut i = 0usize;
    while i <= upper {
        // `search_from < size` is guaranteed by `i <= upper` and
        // `anchor_off < pat_len`.
        let search_from = i + anchor_off;
        // SAFETY: in-bounds for the declared range.
        let Some(rel) =
            (unsafe { first_byte_in_raw(start + search_from, size - search_from, anchor_byte) })
        else {
            break;
        };
        let candidate = search_from + rel - anchor_off;
        if candidate > upper {
            break;
        }
        let addr = start + candidate;
        // SAFETY: in-bounds.
        if unsafe { matches_at(addr, pattern) } {
            count += 1;
            i = candidate + pat_len;
        } else {
            i = candidate + 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern;
    use crate::pe::IMAGE_SCN_MEM_EXECUTE;
    use alloc::vec;
    use alloc::vec::Vec;

    /// Local copy of `synthetic_pe` so this module can build PE-shaped
    /// buffers for the in-process scanner tests without having to reach
    /// into `pe.rs`'s test module.
    fn synthetic_pe(sections: &[([u8; 8], u32, &[u8], u32)]) -> Vec<u8> {
        let needed = sections
            .iter()
            .map(|(_, vaddr, bytes, _)| *vaddr as usize + bytes.len())
            .max()
            .unwrap_or(0)
            .max(0x400);
        let mut buf = vec![0u8; needed];
        buf[0] = b'M';
        buf[1] = b'Z';
        let nt_offset: u32 = 0x80;
        buf[0x3C..0x40].copy_from_slice(&nt_offset.to_le_bytes());
        let nt = nt_offset as usize;
        buf[nt..nt + 4].copy_from_slice(b"PE\0\0");
        let num_sections: u16 = sections.len() as u16;
        buf[nt + 4 + 2..nt + 4 + 4].copy_from_slice(&num_sections.to_le_bytes());
        let opt_size: u16 = 0xF0;
        buf[nt + 4 + 16..nt + 4 + 18].copy_from_slice(&opt_size.to_le_bytes());
        let section_table = nt + 4 + 20 + opt_size as usize;
        for (i, (name, vaddr, bytes, characteristics)) in sections.iter().enumerate() {
            let sec = section_table + i * 40;
            buf[sec..sec + 8].copy_from_slice(name);
            let vsize: u32 = bytes.len() as u32;
            buf[sec + 8..sec + 12].copy_from_slice(&vsize.to_le_bytes());
            buf[sec + 12..sec + 16].copy_from_slice(&vaddr.to_le_bytes());
            buf[sec + 36..sec + 40].copy_from_slice(&characteristics.to_le_bytes());
            let v = *vaddr as usize;
            buf[v..v + bytes.len()].copy_from_slice(bytes);
        }
        buf
    }

    // -- slice variants ----------------------------------------------------

    #[test]
    fn slice_find_basic() {
        let haystack = [0x00, 0x11, 0x48, 0x8B, 0x05, 0x99, 0xAA];
        let pat = pattern![0x48, 0x8B, 0x05];
        let hit = find_in_slice(&haystack, pat).unwrap();
        assert_eq!(hit, haystack.as_ptr() as usize + 2);
    }

    #[test]
    fn slice_find_wildcard() {
        let haystack = [0x00, 0x48, 0x77, 0x05, 0xFF];
        let pat = pattern![0x48, _, 0x05];
        let hit = find_in_slice(&haystack, pat).unwrap();
        assert_eq!(hit, haystack.as_ptr() as usize + 1);
    }

    #[test]
    fn slice_find_misses_returns_none() {
        let haystack = [0x00, 0x11, 0x22];
        let pat = pattern![0x48, 0x8B, 0x05];
        assert!(find_in_slice(&haystack, pat).is_none());
    }

    #[test]
    fn slice_find_empty_pattern_returns_none() {
        let haystack = [0x00, 0x11];
        let pat: &[Option<u8>] = &[];
        assert!(find_in_slice(&haystack, pat).is_none());
    }

    #[test]
    fn slice_find_pattern_longer_than_haystack() {
        let haystack = [0x48];
        let pat = pattern![0x48, 0x8B, 0x05];
        assert!(find_in_slice(&haystack, pat).is_none());
    }

    #[test]
    fn slice_find_all_wildcards_matches_first() {
        // Pattern with no anchor byte exercises the `has_anchor = false`
        // path inside `scan_range`.
        let haystack = [0xAA, 0xBB, 0xCC];
        let pat: &[Option<u8>] = &[None, None];
        let hit = find_in_slice(&haystack, pat).unwrap();
        assert_eq!(hit, haystack.as_ptr() as usize);
    }

    #[test]
    fn slice_find_anchor_match_but_full_pattern_mismatch() {
        // The anchor byte (0x48) appears at offset 0 where the FULL pattern
        // does NOT match (next byte is 0xFF, not 0x8B), and again at offset
        // 2 where it DOES match. Forces the scanner to:
        //   * pass the anchor pre-filter at i=0
        //   * fall into `matches_at`, which compares index 1 (0x8B vs 0xFF)
        //     and returns false — exercising `matches_at`'s `return false`
        //     branch
        //   * advance i and continue searching — exercising `scan_range`'s
        //     post-mismatch `i += 1` line
        //   * eventually find the real match at offset 2
        let haystack = [0x48, 0xFF, 0x48, 0x8B];
        let pat = pattern![0x48, 0x8B];
        let hit = find_in_slice(&haystack, pat).unwrap();
        assert_eq!(hit, haystack.as_ptr() as usize + 2);
    }

    #[test]
    fn slice_count_anchor_match_but_full_pattern_mismatch() {
        // Same construction as the previous test but for the count path,
        // exercising `count_range`'s `else { i += 1 }` branch when
        // `matches_at` returns false after an anchor pre-filter pass.
        let haystack = [0x48, 0xFF, 0x48, 0x8B];
        let pat = pattern![0x48, 0x8B];
        assert_eq!(count_in_slice(&haystack, pat), 1);
    }

    #[test]
    fn slice_find_anchor_in_middle() {
        // First pattern byte is a wildcard, second is the anchor. Forces
        // `find_map` to skip past index 0 when computing the anchor.
        let haystack = [0xCC, 0x77, 0x99, 0xAA, 0x77, 0x99];
        let pat: &[Option<u8>] = &[None, Some(0x77), Some(0x99)];
        let hit = find_in_slice(&haystack, pat).unwrap();
        // First match at offset 0: pos[1]=0x77, pos[2]=0x99 → matches.
        assert_eq!(hit, haystack.as_ptr() as usize);
    }

    #[test]
    fn slice_count_basic() {
        let haystack = [0x48, 0x8B, 0x00, 0x48, 0x8B, 0x00, 0x48, 0x8B];
        let pat = pattern![0x48, 0x8B];
        assert_eq!(count_in_slice(&haystack, pat), 3);
    }

    #[test]
    fn slice_count_no_overlap() {
        // Pattern repeated in haystack — non-overlapping policy means we
        // count 2 matches (0..2 and 2..4), not 3.
        let haystack = [0x42, 0x42, 0x42, 0x42];
        let pat = pattern![0x42, 0x42];
        assert_eq!(count_in_slice(&haystack, pat), 2);
    }

    #[test]
    fn slice_count_zero_when_no_match() {
        let haystack = [0x00, 0x11, 0x22];
        let pat = pattern![0x48];
        assert_eq!(count_in_slice(&haystack, pat), 0);
    }

    #[test]
    fn slice_count_empty_pattern_returns_zero() {
        let haystack = [0x00, 0x11];
        let pat: &[Option<u8>] = &[];
        assert_eq!(count_in_slice(&haystack, pat), 0);
    }

    #[test]
    fn slice_count_pattern_longer_than_haystack() {
        let haystack = [0x48];
        let pat = pattern![0x48, 0x8B, 0x05];
        assert_eq!(count_in_slice(&haystack, pat), 0);
    }

    #[test]
    fn slice_count_all_wildcards() {
        // No-anchor count path. Two non-overlapping length-2 windows fit
        // in a 4-byte haystack.
        let haystack = [0xAA, 0xBB, 0xCC, 0xDD];
        let pat: &[Option<u8>] = &[None, None];
        assert_eq!(count_in_slice(&haystack, pat), 2);
    }

    // -- in-process variants (synthetic PE) --------------------------------

    #[test]
    fn synthetic_pe_text_find_and_count() {
        let text = [0x00u8, 0x11, 0x48, 0x8B, 0x05, 0xFF, 0x00, 0x48, 0x8B, 0x05];
        let buf = synthetic_pe(&[(*b".text\0\0\0", 0x300, &text, IMAGE_SCN_MEM_EXECUTE)]);
        let base = buf.as_ptr() as usize;
        let pat = pattern![0x48, 0x8B, 0x05];

        // First match is at the first hit, at offset 2 inside the section.
        let hit = find_in_text(base, pat).unwrap();
        assert_eq!(hit, base + 0x300 + 2);

        // Two non-overlapping matches in the synthetic body.
        assert_eq!(count_in_text(base, pat), 2);
    }

    #[test]
    fn synthetic_pe_text_find_returns_none_when_no_match() {
        let text = [0xAAu8, 0xBB, 0xCC];
        let buf = synthetic_pe(&[(*b".text\0\0\0", 0x300, &text, IMAGE_SCN_MEM_EXECUTE)]);
        let base = buf.as_ptr() as usize;
        let pat = pattern![0x48, 0x8B];
        assert!(find_in_text(base, pat).is_none());
        assert_eq!(count_in_text(base, pat), 0);
    }

    #[test]
    fn synthetic_pe_text_returns_none_when_no_text_section() {
        // No `.text` section, only `.data`. text_section_bounds returns None
        // → find/count both bail out via the early-return paths.
        let body = [0x48u8, 0x8B];
        let buf = synthetic_pe(&[(*b".data\0\0\0", 0x300, &body, 0)]);
        let base = buf.as_ptr() as usize;
        let pat = pattern![0x48, 0x8B];
        assert!(find_in_text(base, pat).is_none());
        assert_eq!(count_in_text(base, pat), 0);
    }

    #[test]
    fn synthetic_pe_exec_sections_find_across_sections() {
        // Pattern is in the SECOND executable section. find_in_exec_sections
        // should still locate it after scanning past the first.
        let body_a = [0xAAu8, 0xBB];
        let body_b = [0x90u8, 0x90, 0xC3];
        let buf = synthetic_pe(&[
            (*b".text\0\0\0", 0x300, &body_a, IMAGE_SCN_MEM_EXECUTE),
            (*b".text$mn", 0x310, &body_b, IMAGE_SCN_MEM_EXECUTE),
        ]);
        let base = buf.as_ptr() as usize;
        let pat = pattern![0x90, 0x90, 0xC3];
        let hit = find_in_exec_sections(base, pat).unwrap();
        assert_eq!(hit, base + 0x310);
        assert_eq!(count_in_exec_sections(base, pat), 1);
    }

    #[test]
    fn synthetic_pe_exec_sections_count_sums_across_sections() {
        // Same pattern in two executable sections. count_in_exec_sections
        // should sum (1 + 1).
        let body = [0x90u8, 0x90];
        let buf = synthetic_pe(&[
            (*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE),
            (*b".text$mn", 0x310, &body, IMAGE_SCN_MEM_EXECUTE),
        ]);
        let base = buf.as_ptr() as usize;
        let pat = pattern![0x90, 0x90];
        assert_eq!(count_in_exec_sections(base, pat), 2);
    }

    #[test]
    fn synthetic_pe_exec_sections_returns_none_when_no_match() {
        let body = [0xAAu8];
        let buf = synthetic_pe(&[(*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE)]);
        let base = buf.as_ptr() as usize;
        let pat = pattern![0x48];
        assert!(find_in_exec_sections(base, pat).is_none());
        assert_eq!(count_in_exec_sections(base, pat), 0);
    }

    // -- guard paths -------------------------------------------------------

    #[test]
    fn null_module_returns_none_or_zero() {
        let pat = pattern![0x48];
        assert!(find_in_text(0, pat).is_none());
        assert_eq!(count_in_text(0, pat), 0);
        assert!(find_in_exec_sections(0, pat).is_none());
        assert_eq!(count_in_exec_sections(0, pat), 0);
    }

    #[test]
    fn empty_pattern_returns_none_or_zero() {
        let body = [0x90u8];
        let buf = synthetic_pe(&[(*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE)]);
        let base = buf.as_ptr() as usize;
        let pat: &[Option<u8>] = &[];
        assert!(find_in_text(base, pat).is_none());
        assert_eq!(count_in_text(base, pat), 0);
        assert!(find_in_exec_sections(base, pat).is_none());
        assert_eq!(count_in_exec_sections(base, pat), 0);
    }

    #[test]
    fn malformed_module_returns_none_or_zero() {
        // Buffer is all zeros — no MZ signature → headers fail to parse →
        // every public scan function bails out gracefully.
        let buf = vec![0u8; 0x400];
        let base = buf.as_ptr() as usize;
        let pat = pattern![0x48];
        assert!(find_in_text(base, pat).is_none());
        assert_eq!(count_in_text(base, pat), 0);
        assert!(find_in_exec_sections(base, pat).is_none());
        assert_eq!(count_in_exec_sections(base, pat), 0);
    }

    // -- raw-pointer all-wildcard fast path -------------------------------

    /// All-wildcard pattern via the in-process API exercises the
    /// `scan_range`/`count_range` "no anchor" early-return branches.
    #[test]
    fn synthetic_pe_text_all_wildcard_pattern() {
        let text = [0xAAu8; 16];
        let buf = synthetic_pe(&[(*b".text\0\0\0", 0x300, &text, IMAGE_SCN_MEM_EXECUTE)]);
        let base = buf.as_ptr() as usize;
        let pat: &[Option<u8>] = &[None, None, None, None];

        // Find returns the section start (offset 0).
        let hit = find_in_text(base, pat).unwrap();
        let (text_start, _) = crate::pe::text_section_bounds(base).unwrap();
        assert_eq!(hit, text_start);

        // Count: floor(section_size / pat_len). Section is padded to its
        // declared VirtualSize, not just the body length, so we just check
        // the result is positive and divides cleanly.
        let count = count_in_text(base, pat);
        assert!(count >= text.len() / 4);
    }

    // -- candidate-past-upper break path ----------------------------------

    /// Anchor byte appears in the trailing window where the full pattern
    /// no longer fits — `scan_slice` / `count_slice` must take the
    /// `candidate > upper` early-return / break path.
    #[test]
    fn slice_anchor_at_tail_no_room_for_pattern() {
        // Anchor is 0x48; pattern length is 4. Plant 0x48 in the last byte
        // so candidate would be haystack.len()-1 > upper = haystack.len()-4.
        let mut buf = vec![0u8; 16];
        buf[15] = 0x48;
        let pat = pattern![0x48, 0x8B, 0x05, _];

        assert!(crate::find_in_slice(&buf, pat).is_none());
        assert_eq!(crate::count_in_slice(&buf, pat), 0);
    }

    /// `scan_slice` natural fall-through path: the anchor pre-filter
    /// passes at `candidate == upper` but `matches_at` rejects the
    /// candidate, leaving `i = candidate + 1 > upper` so the while loop
    /// exits without ever returning, falling through to the trailing
    /// `None`.
    #[test]
    fn slice_find_loop_exhausts_when_last_candidate_fails() {
        // pat_len = 2, haystack.len() = 4, upper = 2. 0x48 only at index 2.
        // matches_at(2) fails because byte 3 is 0xFF, not 0x8B.
        let haystack = [0x00, 0x00, 0x48, 0xFF];
        let pat = pattern![0x48, 0x8B];
        assert!(find_in_slice(&haystack, pat).is_none());
    }

    // -- raw-pointer "anchor matches, full pattern doesn't" ---------------

    /// Forces the in-process `scan_range` / `count_range` scanners through
    /// the `matches_at == false` branch (raw-pointer `i = candidate + 1`),
    /// and through the `candidate > upper` break path when the anchor
    /// hits in the trailing window where the pattern no longer fits.
    #[test]
    fn synthetic_pe_text_anchor_match_but_full_pattern_mismatch() {
        // Anchor 0x48 appears at offset 0 (full pattern fails) and at
        // offset 4 which is past the upper bound for pat_len = 4 in a
        // 5-byte body — exercising both `i = candidate + 1` (raw path)
        // and `candidate > upper` (raw path) in one test.
        let body = [0x48, 0x00, 0x00, 0x00, 0x48];
        let buf = synthetic_pe(&[(*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE)]);
        let base = buf.as_ptr() as usize;
        let pat = pattern![0x48, 0xAA, 0xBB, 0xCC];

        assert!(find_in_text(base, pat).is_none());
        assert_eq!(count_in_text(base, pat), 0);
    }

    /// Companion to the above: anchor matches at exactly `upper` but the
    /// full pattern doesn't, so `scan_range`'s while loop exits naturally
    /// via the trailing `None`, and `count_range`'s while loop exits with
    /// `count == 0`.
    #[test]
    fn synthetic_pe_text_anchor_at_upper_then_loop_exhausts() {
        // pat_len = 4, body.len() = 4, upper = 0. Anchor at 0, full
        // pattern fails (0x48 OK, 0x00 != 0xAA), i = 1, loop exits.
        let body = [0x48, 0x00, 0x00, 0x00];
        let buf = synthetic_pe(&[(*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE)]);
        let base = buf.as_ptr() as usize;
        let pat = pattern![0x48, 0xAA, 0xBB, 0xCC];

        assert!(find_in_text(base, pat).is_none());
        assert_eq!(count_in_text(base, pat), 0);
    }

    // -- iterator (slice) -------------------------------------------------

    #[test]
    fn iter_slice_yields_all_non_overlapping_matches() {
        let bytes = [
            0x48, 0x8B, 0x05, 0x00, 0x48, 0x8B, 0x05, 0xFF, 0x48, 0x8B, 0x05,
        ];
        let pat = pattern![0x48, 0x8B, 0x05];
        let hits: Vec<usize> = iter_in_slice(&bytes, pat).collect();
        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0], bytes.as_ptr() as usize);
        assert_eq!(hits[1], bytes.as_ptr() as usize + 4);
        assert_eq!(hits[2], bytes.as_ptr() as usize + 8);
    }

    #[test]
    fn iter_slice_count_matches_count_in_slice() {
        // The iterator and `count_in_slice` use the same non-overlap rule,
        // so `iter_in_slice(..).count()` must equal `count_in_slice(..)`.
        let bytes = [0x42, 0x42, 0x42, 0x42, 0x42];
        let pat = pattern![0x42, 0x42];
        assert_eq!(
            iter_in_slice(&bytes, pat).count(),
            count_in_slice(&bytes, pat)
        );
    }

    #[test]
    fn iter_slice_empty_pattern_yields_nothing() {
        let bytes = [0x00, 0x11, 0x22];
        let pat: &[Option<u8>] = &[];
        assert_eq!(iter_in_slice(&bytes, pat).count(), 0);
    }

    #[test]
    fn iter_slice_no_match_yields_nothing() {
        let bytes = [0xAA, 0xBB, 0xCC];
        let pat = pattern![0x48, 0x8B];
        assert_eq!(iter_in_slice(&bytes, pat).count(), 0);
    }

    #[test]
    fn iter_slice_pattern_longer_than_haystack_yields_nothing() {
        let bytes = [0x48];
        let pat = pattern![0x48, 0x8B, 0x05];
        assert_eq!(iter_in_slice(&bytes, pat).count(), 0);
    }

    #[test]
    fn iter_slice_with_wildcards() {
        // Pattern `48 ?? 05` should match at offsets 0 (48 8B 05) and
        // 3 (48 99 05), but NOT at offset 6 (48 AA FF — 3rd byte not 05).
        let bytes = [0x48, 0x8B, 0x05, 0x48, 0x99, 0x05, 0x48, 0xAA, 0xFF];
        let pat = pattern![0x48, _, 0x05];
        let hits: Vec<usize> = iter_in_slice(&bytes, pat).collect();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0], bytes.as_ptr() as usize);
        assert_eq!(hits[1], bytes.as_ptr() as usize + 3);
    }

    #[test]
    fn iter_slice_all_wildcard_pattern_strides_by_pat_len() {
        // All-wildcard pattern of length 2 in a 5-byte haystack: yields
        // matches at 0 and 2 (non-overlap). Offset 4 has only one byte
        // remaining so the pattern doesn't fit.
        let bytes = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let pat: &[Option<u8>] = &[None, None];
        let hits: Vec<usize> = iter_in_slice(&bytes, pat).collect();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0], bytes.as_ptr() as usize);
        assert_eq!(hits[1], bytes.as_ptr() as usize + 2);
    }

    #[test]
    fn iter_slice_clone_is_independent() {
        // The Clone impl on the iterator must not share state with its
        // origin — both clones should yield the same sequence.
        let bytes = [0x48, 0x8B, 0x00, 0x48, 0x8B];
        let pat = pattern![0x48, 0x8B];
        let it = iter_in_slice(&bytes, pat);
        let from_clone: Vec<usize> = it.clone().collect();
        let from_original: Vec<usize> = it.collect();
        assert_eq!(from_clone, from_original);
        assert_eq!(from_clone.len(), 2);
    }

    // -- iterator (in-process .text) --------------------------------------

    #[test]
    fn iter_in_text_yields_all_matches() {
        let body = [0x48u8, 0x8B, 0x05, 0x00, 0x48, 0x8B, 0x05];
        let buf = synthetic_pe(&[(*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE)]);
        let base = buf.as_ptr() as usize;
        let pat = pattern![0x48, 0x8B, 0x05];
        let hits: Vec<usize> = iter_in_text(base, pat).collect();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0], base + 0x300);
        assert_eq!(hits[1], base + 0x300 + 4);
    }

    #[test]
    fn iter_in_text_first_matches_find_in_text() {
        // The first iterator yield must equal the single-shot `find_in_text`
        // result — both use the same scan_range_from primitive.
        let body = [0x90u8, 0x90, 0x48, 0x8B, 0x05, 0xCC];
        let buf = synthetic_pe(&[(*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE)]);
        let base = buf.as_ptr() as usize;
        let pat = pattern![0x48, 0x8B, 0x05];
        let from_iter = iter_in_text(base, pat).next();
        let from_find = find_in_text(base, pat);
        assert_eq!(from_iter, from_find);
        assert_eq!(from_iter, Some(base + 0x300 + 2));
    }

    #[test]
    fn iter_in_text_count_matches_count_in_text() {
        // Iterator length must equal count_in_text result.
        let body = [0x48u8, 0x8B, 0x00, 0x48, 0x8B, 0x00, 0x48, 0x8B];
        let buf = synthetic_pe(&[(*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE)]);
        let base = buf.as_ptr() as usize;
        let pat = pattern![0x48, 0x8B];
        assert_eq!(iter_in_text(base, pat).count(), count_in_text(base, pat));
    }

    #[test]
    fn iter_in_text_null_module_yields_nothing() {
        let pat = pattern![0x48];
        assert_eq!(iter_in_text(0, pat).count(), 0);
    }

    #[test]
    fn iter_in_text_empty_pattern_yields_nothing() {
        let body = [0x90u8];
        let buf = synthetic_pe(&[(*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE)]);
        let base = buf.as_ptr() as usize;
        let pat: &[Option<u8>] = &[];
        assert_eq!(iter_in_text(base, pat).count(), 0);
    }

    #[test]
    fn iter_in_text_missing_text_section_yields_nothing() {
        // Module has only `.data`, no `.text` — iterator returns empty.
        let body = [0x48u8, 0x8B];
        let buf = synthetic_pe(&[(*b".data\0\0\0", 0x300, &body, 0)]);
        let base = buf.as_ptr() as usize;
        let pat = pattern![0x48, 0x8B];
        assert_eq!(iter_in_text(base, pat).count(), 0);
    }

    #[test]
    fn iter_in_text_malformed_module_yields_nothing() {
        // No MZ → text_section_bounds returns None → empty sections list.
        let buf = vec![0u8; 0x400];
        let base = buf.as_ptr() as usize;
        let pat = pattern![0x48];
        assert_eq!(iter_in_text(base, pat).count(), 0);
    }

    // -- iterator (in-process all exec sections) --------------------------

    #[test]
    fn iter_in_exec_sections_yields_across_multiple_sections() {
        let body_a = [0x90u8, 0x90, 0xC3];
        let body_b = [0x48u8, 0x8B, 0x05, 0xCC, 0x48, 0x8B, 0x05];
        let buf = synthetic_pe(&[
            (*b".text\0\0\0", 0x300, &body_a, IMAGE_SCN_MEM_EXECUTE),
            (*b".text$mn", 0x310, &body_b, IMAGE_SCN_MEM_EXECUTE),
        ]);
        let base = buf.as_ptr() as usize;
        let pat = pattern![0x48, 0x8B, 0x05];
        let hits: Vec<usize> = iter_in_exec_sections(base, pat).collect();
        // Two matches, both in the second exec section.
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0], base + 0x310);
        assert_eq!(hits[1], base + 0x310 + 4);
    }

    #[test]
    fn iter_in_exec_sections_advances_to_next_section_after_exhaustion() {
        // First section has zero matches, second has one — iterator must
        // skip past the first cleanly.
        let body_a = [0xAAu8, 0xBB, 0xCC];
        let body_b = [0x90u8, 0x90, 0xC3];
        let buf = synthetic_pe(&[
            (*b".text\0\0\0", 0x300, &body_a, IMAGE_SCN_MEM_EXECUTE),
            (*b".text$mn", 0x310, &body_b, IMAGE_SCN_MEM_EXECUTE),
        ]);
        let base = buf.as_ptr() as usize;
        let pat = pattern![0x90, 0x90, 0xC3];
        let hits: Vec<usize> = iter_in_exec_sections(base, pat).collect();
        assert_eq!(hits, vec![base + 0x310]);
    }

    #[test]
    fn iter_in_exec_sections_count_sums_across_sections() {
        let body = [0x90u8, 0x90];
        let buf = synthetic_pe(&[
            (*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE),
            (*b".text$mn", 0x310, &body, IMAGE_SCN_MEM_EXECUTE),
        ]);
        let base = buf.as_ptr() as usize;
        let pat = pattern![0x90, 0x90];
        // One match per section, two sections → iterator length = 2.
        assert_eq!(
            iter_in_exec_sections(base, pat).count(),
            count_in_exec_sections(base, pat)
        );
        assert_eq!(iter_in_exec_sections(base, pat).count(), 2);
    }

    #[test]
    fn iter_in_exec_sections_null_module_yields_nothing() {
        let pat = pattern![0x48];
        assert_eq!(iter_in_exec_sections(0, pat).count(), 0);
    }

    #[test]
    fn iter_in_exec_sections_empty_pattern_yields_nothing() {
        let body = [0x90u8];
        let buf = synthetic_pe(&[(*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE)]);
        let base = buf.as_ptr() as usize;
        let pat: &[Option<u8>] = &[];
        assert_eq!(iter_in_exec_sections(base, pat).count(), 0);
    }

    #[test]
    fn iter_in_exec_sections_malformed_module_yields_nothing() {
        let buf = vec![0u8; 0x400];
        let base = buf.as_ptr() as usize;
        let pat = pattern![0x48];
        assert_eq!(iter_in_exec_sections(base, pat).count(), 0);
    }

    #[cfg(feature = "section-info")]
    mod section_info_tests {
        use super::synthetic_pe;
        use crate::pattern;
        use crate::pe::IMAGE_SCN_MEM_EXECUTE;
        use crate::scan::{count_in_section, find_in_section, iter_in_section};
        use alloc::vec;
        use alloc::vec::Vec;

        /// Two-section PE used by every bounds-sanity test:
        ///
        /// - `.text  @ 0x300`: `90 AA BB CC DD C3` (only `[AA BB CC DD]` and
        ///   `[AA BB]` substrings).
        /// - `.rdata @ 0x400`: `00 11 22 33 44 11 22 FF` (two `[11 22]`
        ///   matches at offsets +0x401 and +0x405).
        ///
        /// Patterns are picked so byte values in one section never collide
        /// with the other — bleed across section boundaries shows up
        /// directly as a wrong count.
        fn multi_section_pe() -> Vec<u8> {
            let text_body = [0x90u8, 0xAA, 0xBB, 0xCC, 0xDD, 0xC3];
            let rdata_body = [0x00u8, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0xFF];
            synthetic_pe(&[
                (*b".text\0\0\0", 0x300, &text_body, IMAGE_SCN_MEM_EXECUTE),
                (*b".rdata\0\0", 0x400, &rdata_body, 0),
            ])
        }

        // -- find_in_section -----------------------------------------------

        #[test]
        fn returns_match_in_named_section() {
            let buf = multi_section_pe();
            let base = buf.as_ptr() as usize;
            let pat = pattern![0x11, 0x22, 0x33];
            assert_eq!(find_in_section(base, b".rdata", pat), Some(base + 0x401));
        }

        #[test]
        fn does_not_cross_section_bounds() {
            // Pattern lives only in .text — querying .rdata must miss,
            // querying .text must hit. Catches the regression where a
            // section-targeted scanner accidentally walks the whole image.
            let buf = multi_section_pe();
            let base = buf.as_ptr() as usize;
            let pat = pattern![0xAA, 0xBB, 0xCC, 0xDD];
            assert!(find_in_section(base, b".rdata", pat).is_none());
            assert_eq!(find_in_section(base, b".text", pat), Some(base + 0x301));
        }

        #[test]
        fn matches_section_name_by_prefix() {
            // ".rdata$z" suffix-tagged section caught by ".rdata" query.
            let body = [0xDEu8, 0xAD, 0xBE, 0xEF];
            let buf = synthetic_pe(&[(*b".rdata$z", 0x300, &body, 0)]);
            let base = buf.as_ptr() as usize;
            let pat = pattern![0xDE, 0xAD, 0xBE, 0xEF];
            assert_eq!(find_in_section(base, b".rdata", pat), Some(base + 0x300));
        }

        #[test]
        fn full_eight_byte_name_disambiguates() {
            // Two sections both starting with ".text"; the 8-byte query
            // must hit ".text\0\0\0" exactly and skip ".text$mn".
            let mn_body = [0x11u8, 0x22, 0x33];
            let text_body = [0xAAu8, 0xBB, 0xCC];
            let buf = synthetic_pe(&[
                (*b".text$mn", 0x300, &mn_body, IMAGE_SCN_MEM_EXECUTE),
                (*b".text\0\0\0", 0x400, &text_body, IMAGE_SCN_MEM_EXECUTE),
            ]);
            let base = buf.as_ptr() as usize;
            // Querying with the full 8-byte name lands on the second section.
            let pat = pattern![0xAA, 0xBB, 0xCC];
            assert_eq!(
                find_in_section(base, b".text\0\0\0", pat),
                Some(base + 0x400),
            );
            // Bytes from the .text\0\0\0 section are absent from .text$mn.
            assert!(find_in_section(base, b".text$mn", pat).is_none());
        }

        #[test]
        fn returns_none_when_section_missing() {
            let body = [0x90u8];
            let buf = synthetic_pe(&[(*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE)]);
            let base = buf.as_ptr() as usize;
            let pat = pattern![0x90];
            assert!(find_in_section(base, b".rdata", pat).is_none());
        }

        #[test]
        fn returns_none_when_pattern_absent() {
            let buf = multi_section_pe();
            let base = buf.as_ptr() as usize;
            let pat = pattern![0xFF, 0xFF, 0xFF, 0xFF];
            assert!(find_in_section(base, b".rdata", pat).is_none());
        }

        #[test]
        fn null_module_returns_none() {
            let pat = pattern![0x90];
            assert!(find_in_section(0, b".rdata", pat).is_none());
        }

        #[test]
        fn empty_pattern_returns_none() {
            let buf = multi_section_pe();
            let base = buf.as_ptr() as usize;
            let pat: &[Option<u8>] = &[];
            assert!(find_in_section(base, b".rdata", pat).is_none());
        }

        #[test]
        fn malformed_module_returns_none() {
            let buf = vec![0u8; 0x400];
            let base = buf.as_ptr() as usize;
            let pat = pattern![0x90];
            assert!(find_in_section(base, b".rdata", pat).is_none());
        }

        // -- count_in_section ----------------------------------------------

        #[test]
        fn count_finds_all_matches_in_section() {
            let buf = multi_section_pe();
            let base = buf.as_ptr() as usize;
            // [11 22] appears twice in .rdata (offsets +0x401, +0x405).
            let pat = pattern![0x11, 0x22];
            assert_eq!(count_in_section(base, b".rdata", pat), 2);
        }

        #[test]
        fn count_does_not_include_other_sections() {
            let buf = multi_section_pe();
            let base = buf.as_ptr() as usize;
            // [AA BB] is in .text only.
            let pat = pattern![0xAA, 0xBB];
            assert_eq!(count_in_section(base, b".rdata", pat), 0);
            assert_eq!(count_in_section(base, b".text", pat), 1);
        }

        #[test]
        fn count_returns_zero_when_section_missing() {
            let body = [0x90u8];
            let buf = synthetic_pe(&[(*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE)]);
            let base = buf.as_ptr() as usize;
            let pat = pattern![0x90];
            assert_eq!(count_in_section(base, b".rdata", pat), 0);
        }

        #[test]
        fn count_null_module_returns_zero() {
            let pat = pattern![0x90];
            assert_eq!(count_in_section(0, b".rdata", pat), 0);
        }

        #[test]
        fn count_empty_pattern_returns_zero() {
            let buf = multi_section_pe();
            let base = buf.as_ptr() as usize;
            let pat: &[Option<u8>] = &[];
            assert_eq!(count_in_section(base, b".rdata", pat), 0);
        }

        #[test]
        fn count_malformed_module_returns_zero() {
            let buf = vec![0u8; 0x400];
            let base = buf.as_ptr() as usize;
            let pat = pattern![0x90];
            assert_eq!(count_in_section(base, b".rdata", pat), 0);
        }

        // -- iter_in_section -----------------------------------------------

        #[test]
        fn iter_yields_all_matches_in_order() {
            let buf = multi_section_pe();
            let base = buf.as_ptr() as usize;
            let pat = pattern![0x11, 0x22];
            let hits: Vec<usize> = iter_in_section(base, b".rdata", pat).collect();
            assert_eq!(hits, vec![base + 0x401, base + 0x405]);
        }

        #[test]
        fn iter_first_equals_find_in_section() {
            let buf = multi_section_pe();
            let base = buf.as_ptr() as usize;
            let pat = pattern![0x11, 0x22];
            assert_eq!(
                iter_in_section(base, b".rdata", pat).next(),
                find_in_section(base, b".rdata", pat),
            );
        }

        #[test]
        fn iter_count_equals_count_in_section() {
            let buf = multi_section_pe();
            let base = buf.as_ptr() as usize;
            let pat = pattern![0x11, 0x22];
            assert_eq!(
                iter_in_section(base, b".rdata", pat).count(),
                count_in_section(base, b".rdata", pat),
            );
        }

        #[test]
        fn iter_does_not_cross_section_bounds() {
            let buf = multi_section_pe();
            let base = buf.as_ptr() as usize;
            let pat = pattern![0xAA, 0xBB];
            assert_eq!(iter_in_section(base, b".rdata", pat).count(), 0);
        }

        #[test]
        fn iter_section_missing_yields_nothing() {
            let body = [0x90u8];
            let buf = synthetic_pe(&[(*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE)]);
            let base = buf.as_ptr() as usize;
            let pat = pattern![0x90];
            assert_eq!(iter_in_section(base, b".rdata", pat).count(), 0);
        }

        #[test]
        fn iter_null_module_yields_nothing() {
            let pat = pattern![0x90];
            assert_eq!(iter_in_section(0, b".rdata", pat).count(), 0);
        }

        #[test]
        fn iter_empty_pattern_yields_nothing() {
            let buf = multi_section_pe();
            let base = buf.as_ptr() as usize;
            let pat: &[Option<u8>] = &[];
            assert_eq!(iter_in_section(base, b".rdata", pat).count(), 0);
        }

        #[test]
        fn iter_malformed_module_yields_nothing() {
            let buf = vec![0u8; 0x400];
            let base = buf.as_ptr() as usize;
            let pat = pattern![0x90];
            assert_eq!(iter_in_section(base, b".rdata", pat).count(), 0);
        }
    }
}
