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
/// `.text`. Source 2 DLLs (notably `scenesystem.dll` on some builds) split
/// code across multiple sections, and the section named `.text` may not
/// contain the function at all.
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

/// Slice-native scan for the first match.
///
/// Uses [`first_byte_in_slice`] to skip directly to the next plausible
/// candidate offset instead of stepping byte-by-byte. On haystacks where
/// the anchor byte is rare this is dramatically faster than
/// [`scan_range`].
fn scan_slice(haystack: &[u8], pattern: WildcardPattern<'_>) -> Option<usize> {
    let pat_len = pattern.len();
    let upper = haystack.len() - pat_len; // safe: caller checked length
    let Some((anchor_off, anchor_byte)) = anchor(pattern) else {
        // All-wildcard pattern matches at offset 0.
        return Some(0);
    };

    let mut i = 0usize;
    while i <= upper {
        // Search for the anchor byte starting from the current candidate
        // offset (offset by `anchor_off` so the byte we find lines up
        // correctly with the pattern).
        let search_from = i + anchor_off;
        if search_from >= haystack.len() {
            return None;
        }
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

/// Slice-native count of non-overlapping matches.
fn count_slice(haystack: &[u8], pattern: WildcardPattern<'_>) -> usize {
    let pat_len = pattern.len();
    let upper = haystack.len() - pat_len;
    let Some((anchor_off, anchor_byte)) = anchor(pattern) else {
        // All-wildcard pattern: every position matches; non-overlapping
        // count = floor(len / pat_len) + 1 for the trailing zero-length
        // match. We mirror the byte-by-byte semantics: stride = pat_len.
        return haystack.len() / pat_len.max(1);
    };

    let mut count = 0usize;
    let mut i = 0usize;
    while i <= upper {
        let search_from = i + anchor_off;
        if search_from >= haystack.len() {
            break;
        }
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

/// Scan a single contiguous raw byte range for the first match.
///
/// # Safety contract for the unsafe pointer reads
///
/// `start..start+size` must be a readable contiguous range of bytes. For
/// the in-process callers this is guaranteed by the PE section bounds; for
/// the slice variant by Rust's `&[u8]` lifetime + length invariants. The
/// `i <= upper = size - pat_len` loop invariant ensures every read is
/// inside the range.
fn scan_range(start: usize, size: usize, pattern: WildcardPattern<'_>) -> Option<usize> {
    let pat_len = pattern.len();
    if size < pat_len {
        return None;
    }
    let upper = size - pat_len;
    let Some((anchor_off, anchor_byte)) = anchor(pattern) else {
        return Some(start);
    };

    let mut i = 0usize;
    while i <= upper {
        let search_from = i + anchor_off;
        if search_from >= size {
            return None;
        }
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
        return size / pat_len.max(1);
    };

    let mut count = 0usize;
    let mut i = 0usize;
    while i <= upper {
        let search_from = i + anchor_off;
        if search_from >= size {
            break;
        }
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
}
