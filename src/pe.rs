//! Internal PE (Portable Executable) header walking.
//!
//! All public scanning entry points funnel through this module to
//! translate a `module_base: usize` into one or more
//! `(virtual_address, virtual_size)` ranges that are guaranteed
//! readable. The PE format is fixed by the Windows loader, so this
//! module is a straight transcription of the relevant header offsets
//! — no heuristics.
//!
//! Nothing here is part of the public API. The `section-info` feature
//! exposes a few scanner-shaped helpers in [`crate::scan`]
//! (`find_in_section` and friends) plus the [`module_size`] free
//! function; those delegate down to [`find_section`] / [`iter_sections`]
//! below.

use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// PE-format constants
// ---------------------------------------------------------------------------

/// `IMAGE_SCN_MEM_EXECUTE` — section can be executed as code. Set for
/// `.text` and any companion code sections (e.g. `.text$mn`, `.textbss`,
/// jump-table arenas, optimised-layout sections that some compilers and
/// linkers emit).
pub(crate) const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// `IMAGE_SCN_MEM_READ` — section is readable.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;

/// `IMAGE_SCN_MEM_WRITE` — section is writable.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// `IMAGE_DOS_HEADER.e_magic` — `MZ` little-endian.
const DOS_MAGIC_MZ: u16 = 0x5A4D;

/// `IMAGE_NT_HEADERS.Signature` — `PE\0\0` little-endian.
const NT_SIGNATURE_PE: u32 = 0x0000_4550;

/// `IMAGE_DOS_HEADER.e_lfanew` byte offset — file offset of NT headers.
const DOS_E_LFANEW_OFFSET: usize = 0x3C;

/// Size of `IMAGE_FILE_HEADER` in bytes.
const FILE_HEADER_SIZE: usize = 20;

/// Size of one `IMAGE_SECTION_HEADER` entry.
const SECTION_HEADER_SIZE: usize = 40;

/// Byte offset of the optional header relative to NT headers
/// (`Signature` u32 + `IMAGE_FILE_HEADER` 20 bytes).
///
/// Only consumed under the `section-info` feature ([`module_size`])
/// or in `#[cfg(test)]` (the synthetic-PE builder writes the
/// SizeOfImage field at this offset). Gating prevents a `dead_code`
/// warning on default `cargo check` / `cargo build` invocations
/// where neither code path is compiled.
#[cfg(any(feature = "section-info", test))]
const OPTIONAL_HEADER_OFFSET: usize = 4 + FILE_HEADER_SIZE;

/// Byte offset of `IMAGE_OPTIONAL_HEADER.SizeOfImage` *within the
/// optional header*. PE32 and PE32+ both place this field at +56,
/// despite their preceding fields differing in width
/// (`ImageBase` is `u32` in PE32 and `u64` in PE32+; `BaseOfData`
/// is PE32-only). Because the totals come out the same, we can
/// read `SizeOfImage` without distinguishing the two formats.
#[cfg(feature = "section-info")]
const OPTIONAL_HEADER_SIZE_OF_IMAGE_OFFSET: usize = 56;

// ---------------------------------------------------------------------------
// Shared header walker
// ---------------------------------------------------------------------------

/// Parsed PE header layout. Cheap to construct (a few magic-checked
/// reads), so callers re-derive it per call rather than caching.
#[derive(Debug, Clone, Copy)]
struct PeHeaders {
    /// Absolute base address every virtual address is offset from.
    module_base: usize,
    /// Absolute address of the NT headers (`module_base + e_lfanew`).
    /// Used by `module_size` to reach `OptionalHeader.SizeOfImage`.
    #[cfg_attr(not(feature = "section-info"), allow(dead_code))]
    nt: usize,
    /// Absolute address of the first `IMAGE_SECTION_HEADER` entry.
    section_table: usize,
    /// `IMAGE_FILE_HEADER.NumberOfSections`.
    num_sections: usize,
}

/// Validate the DOS + NT magics at `module_base` and return a parsed
/// header handle pointing at the section table.
///
/// Returns `None` if `module_base` is zero, the MZ signature is
/// missing, or the NT `PE\0\0` signature is missing.
#[inline]
fn parse_pe_headers(module_base: usize) -> Option<PeHeaders> {
    if module_base == 0 {
        return None;
    }
    // SAFETY: the MZ + PE magic checks gate every subsequent read.
    // If `module_base` doesn't point at a real PE, one of those
    // checks fails and we return None before any further deref.
    unsafe {
        if *(module_base as *const u16) != DOS_MAGIC_MZ {
            return None;
        }
        let nt_offset = *((module_base + DOS_E_LFANEW_OFFSET) as *const u32) as usize;
        let nt = module_base + nt_offset;
        if *(nt as *const u32) != NT_SIGNATURE_PE {
            return None;
        }
        let file_hdr = nt + 4;
        let num_sections = *((file_hdr + 2) as *const u16) as usize;
        let opt_hdr_size = *((file_hdr + 16) as *const u16) as usize;
        let section_table = file_hdr + FILE_HEADER_SIZE + opt_hdr_size;
        Some(PeHeaders {
            module_base,
            nt,
            section_table,
            num_sections,
        })
    }
}

// ---------------------------------------------------------------------------
// SectionInfo + section enumeration
// ---------------------------------------------------------------------------

/// One section's in-memory layout. All addresses are absolute
/// (already offset by `module_base`).
///
/// Crate-internal: held briefly between section lookup and the range
/// scanners. Never exposed publicly — the feature-gated public APIs
/// take a section name and a pattern and return the same shape of
/// result as the headline scanners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SectionInfo {
    /// Raw 8-byte name from `IMAGE_SECTION_HEADER.Name` (NUL-padded
    /// ASCII for short names).
    pub(crate) name: [u8; 8],
    /// `module_base + VirtualAddress`.
    pub(crate) virtual_address: usize,
    /// `IMAGE_SECTION_HEADER.VirtualSize`.
    pub(crate) virtual_size: usize,
    /// Raw `IMAGE_SCN_*` flag bits.
    pub(crate) characteristics: u32,
}

impl SectionInfo {
    pub(crate) fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }
}

/// Decode one `IMAGE_SECTION_HEADER` at `sec`.
///
/// # Safety
///
/// `sec..sec + SECTION_HEADER_SIZE` must be readable. Inside the
/// validated section table this is guaranteed by `parse_pe_headers`.
#[inline]
unsafe fn read_section_at(sec: usize, module_base: usize) -> SectionInfo {
    let mut name = [0u8; 8];
    core::ptr::copy_nonoverlapping(sec as *const u8, name.as_mut_ptr(), 8);
    // IMAGE_SECTION_HEADER:
    //   +8:  VirtualSize (u32)
    //   +12: VirtualAddress (u32)
    //   +36: Characteristics (u32)
    let virtual_size = *((sec + 8) as *const u32) as usize;
    let virtual_address = *((sec + 12) as *const u32) as usize;
    let characteristics = *((sec + 36) as *const u32);
    SectionInfo {
        name,
        virtual_address: module_base + virtual_address,
        virtual_size,
        characteristics,
    }
}

/// Iterate every section in declaration order. Returns `None` if the
/// headers are malformed.
///
/// Every other section walker in the crate (`exec_sections`,
/// `find_section`, the section-targeted scanners) goes through this
/// one — change the walking logic here and everything else inherits.
#[must_use]
pub(crate) fn iter_sections(module_base: usize) -> Option<impl Iterator<Item = SectionInfo>> {
    let hdr = parse_pe_headers(module_base)?;
    Some((0..hdr.num_sections).map(move |i| {
        let sec = hdr.section_table + i * SECTION_HEADER_SIZE;
        // SAFETY: `sec` is inside the section table validated above.
        unsafe { read_section_at(sec, hdr.module_base) }
    }))
}

/// Find the first section whose 8-byte name starts with `prefix`.
///
/// Prefix is matched against the raw 8 bytes — `b".text"` matches
/// `.text\0\0\0`, `.text$mn`, `.textbss`. Pass the full 8 bytes for
/// an exact match when disambiguation matters.
#[must_use]
pub(crate) fn find_section(module_base: usize, prefix: &[u8]) -> Option<SectionInfo> {
    iter_sections(module_base)?.find(|s| s.name.starts_with(prefix))
}

/// Walk the PE section table at `module_base` and return every
/// executable section as `(virtual_address_absolute, virtual_size)`
/// pairs. Returns `None` if the headers are malformed.
///
/// Tuple shape — `find_in_exec_sections` and friends consume it
/// directly.
pub(crate) fn exec_sections(module_base: usize) -> Option<Vec<(usize, usize)>> {
    Some(
        iter_sections(module_base)?
            .filter(SectionInfo::is_executable)
            .map(|s| (s.virtual_address, s.virtual_size))
            .collect(),
    )
}

/// Return the `.text` section's `(virtual_address_absolute,
/// virtual_size)` tuple, or `None` if the headers are malformed or
/// `.text` is missing.
pub(crate) fn text_section_bounds(module_base: usize) -> Option<(usize, usize)> {
    let s = find_section(module_base, b".text")?;
    Some((s.virtual_address, s.virtual_size))
}

// ---------------------------------------------------------------------------
// module_size (feature `section-info`)
// ---------------------------------------------------------------------------

/// Read `IMAGE_OPTIONAL_HEADER.SizeOfImage` — the total mapped size
/// of the module in bytes. The virtual address range
/// `[module_base, module_base + module_size)` covers every section
/// the loader mapped.
///
/// Returns `None` if `module_base` is zero or the headers are
/// malformed.
///
/// Useful for cross-module rel32 disambiguation: after
/// [`crate::resolve_rel32_at`] gives you an absolute target, check
/// whether it lands inside this module or jumps out to another
/// loaded DLL (`ntdll`, `kernel32`, a delay-imported library).
///
/// `pub` rather than `pub(crate)` so `lib.rs` can `pub use` it; the
/// containing `pe` module is private, so users only see it at
/// `pe_sigscan::module_size`.
///
/// # Example
///
/// ```no_run
/// use pe_sigscan::{module_size, find_in_text, pattern, resolve_rel32_at};
/// # let module_base = 0usize;
///
/// const CALL_SIG: &[Option<u8>] = pattern![0xE8, _, _, _, _];
/// if let Some(addr) = find_in_text(module_base, CALL_SIG) {
///     let target = unsafe { resolve_rel32_at(addr, 1, 5) };
///     let size = module_size(module_base).unwrap_or(0);
///     if target >= module_base && target < module_base + size {
///         println!("internal call to {target:#x}");
///     } else {
///         println!("call leaves the module (target {target:#x})");
///     }
/// }
/// ```
#[cfg(feature = "section-info")]
#[must_use]
pub fn module_size(module_base: usize) -> Option<usize> {
    let hdr = parse_pe_headers(module_base)?;
    // SAFETY: `hdr.nt` was validated against the PE signature.
    // SizeOfImage is at OptionalHeader+56, same offset in PE32 and
    // PE32+ — well inside the loader-mapped header region.
    unsafe {
        let size_of_image_addr =
            hdr.nt + OPTIONAL_HEADER_OFFSET + OPTIONAL_HEADER_SIZE_OF_IMAGE_OFFSET;
        Some(*(size_of_image_addr as *const u32) as usize)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    /// Build a minimal PE-shaped byte buffer with a configurable
    /// section list. Each entry is `(name_8b, virtual_address,
    /// text_bytes, characteristics)`. Returns the buffer; the section
    /// payload bytes are copied into the buffer at each section's
    /// declared `virtual_address`.
    ///
    /// Writes a valid `OptionalHeader.SizeOfImage` equal to the total
    /// buffer length so [`module_size`] tests have an inspectable
    /// non-zero value to compare against. The other tests don't read
    /// SizeOfImage, so the extra write is a no-op for them.
    ///
    /// This is intentionally barebones — it is NOT a valid loadable
    /// PE; only the fields the parser reads are populated. Sufficient
    /// to drive every branch in the PE-walking code from a unit test
    /// without needing a real DLL on disk.
    pub(super) fn synthetic_pe(sections: &[([u8; 8], u32, &[u8], u32)]) -> Vec<u8> {
        let needed = sections
            .iter()
            .map(|(_, vaddr, bytes, _)| *vaddr as usize + bytes.len())
            .max()
            .unwrap_or(0)
            .max(0x400);
        let mut buf = vec![0u8; needed];
        // DOS header magic at +0.
        buf[0] = b'M';
        buf[1] = b'Z';
        // e_lfanew at +0x3C → NT headers at 0x80.
        let nt_offset: u32 = 0x80;
        buf[0x3C..0x40].copy_from_slice(&nt_offset.to_le_bytes());
        let nt = nt_offset as usize;
        // NT signature 'PE\0\0' at NT+0.
        buf[nt..nt + 4].copy_from_slice(b"PE\0\0");
        // FILE_HEADER at NT+4: NumberOfSections (u16) at +2.
        let num_sections: u16 = sections.len() as u16;
        buf[nt + 4 + 2..nt + 4 + 4].copy_from_slice(&num_sections.to_le_bytes());
        // SizeOfOptionalHeader (u16) at +16 = 0xF0 (typical PE32+).
        let opt_size: u16 = 0xF0;
        buf[nt + 4 + 16..nt + 4 + 18].copy_from_slice(&opt_size.to_le_bytes());
        // OptionalHeader.SizeOfImage at NT + 24 + 56 (= NT + 80).
        // Same offset in PE32 and PE32+.
        let size_of_image: u32 = needed as u32;
        let soi_offset = nt + OPTIONAL_HEADER_OFFSET + 56;
        buf[soi_offset..soi_offset + 4].copy_from_slice(&size_of_image.to_le_bytes());
        // Section table starts at NT+4+20+opt_size.
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

    // -- parse_pe_headers (the shared helper everything uses) -------------

    #[test]
    fn parse_pe_headers_returns_none_for_zero_base() {
        assert!(parse_pe_headers(0).is_none());
    }

    #[test]
    fn parse_pe_headers_returns_none_for_missing_mz() {
        let buf = vec![0u8; 0x400];
        assert!(parse_pe_headers(buf.as_ptr() as usize).is_none());
    }

    #[test]
    fn parse_pe_headers_returns_none_for_missing_pe_sig() {
        let mut buf = vec![0u8; 0x400];
        buf[0] = b'M';
        buf[1] = b'Z';
        let nt_offset: u32 = 0x80;
        buf[0x3C..0x40].copy_from_slice(&nt_offset.to_le_bytes());
        // No 'PE\0\0' planted → NT-sig check fails.
        assert!(parse_pe_headers(buf.as_ptr() as usize).is_none());
    }

    #[test]
    fn parse_pe_headers_walks_to_section_table() {
        let body = [0x90u8];
        let buf = synthetic_pe(&[(*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE)]);
        let hdr = parse_pe_headers(buf.as_ptr() as usize).unwrap();
        assert_eq!(hdr.num_sections, 1);
        assert_eq!(hdr.module_base, buf.as_ptr() as usize);
        // Section table is at NT+4+20+opt_size = 0x80+24+0xF0 = 0x188.
        assert_eq!(hdr.section_table, buf.as_ptr() as usize + 0x80 + 24 + 0xF0);
    }

    // -- iter_sections / find_section -------------------------------------

    #[test]
    fn iter_sections_yields_every_section_in_order() {
        let body_a = [0x90u8, 0xC3];
        let body_b = [0xAAu8, 0xBB];
        let body_c = [0xCCu8];
        let buf = synthetic_pe(&[
            (*b".text\0\0\0", 0x300, &body_a, IMAGE_SCN_MEM_EXECUTE),
            (*b".rdata\0\0", 0x310, &body_b, IMAGE_SCN_MEM_READ),
            (
                *b".data\0\0\0",
                0x320,
                &body_c,
                IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
            ),
        ]);
        let base = buf.as_ptr() as usize;
        let secs: Vec<SectionInfo> = iter_sections(base).unwrap().collect();
        assert_eq!(secs.len(), 3);
        assert_eq!(&secs[0].name, b".text\0\0\0");
        assert_eq!(secs[0].virtual_address, base + 0x300);
        assert_eq!(secs[0].virtual_size, body_a.len());
        assert!(secs[0].is_executable());
        assert_eq!(&secs[1].name, b".rdata\0\0");
        assert!(!secs[1].is_executable());
        assert_eq!(&secs[2].name, b".data\0\0\0");
        assert!(!secs[2].is_executable());
    }

    #[test]
    fn iter_sections_returns_none_for_zero_base() {
        assert!(iter_sections(0).is_none());
    }

    #[test]
    fn iter_sections_returns_none_for_malformed_module() {
        let buf = vec![0u8; 0x400];
        assert!(iter_sections(buf.as_ptr() as usize).is_none());
    }

    #[test]
    fn find_section_prefix_matches_companion_sections() {
        let body = [0x90u8];
        let buf = synthetic_pe(&[
            (*b".text$mn", 0x300, &body, IMAGE_SCN_MEM_EXECUTE),
            (*b".data\0\0\0", 0x310, &body, 0),
        ]);
        let base = buf.as_ptr() as usize;
        // Prefix b".text" matches `.text$mn`.
        let s = find_section(base, b".text").unwrap();
        assert_eq!(&s.name, b".text$mn");
        assert_eq!(s.virtual_address, base + 0x300);
    }

    #[test]
    fn find_section_returns_none_when_absent() {
        let body = [0x90u8];
        let buf = synthetic_pe(&[(*b".data\0\0\0", 0x300, &body, 0)]);
        let base = buf.as_ptr() as usize;
        assert!(find_section(base, b".text").is_none());
    }

    #[test]
    fn find_section_exact_8_byte_name_disambiguates() {
        let body = [0x90u8];
        let buf = synthetic_pe(&[
            (*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE),
            (*b".text$mn", 0x310, &body, IMAGE_SCN_MEM_EXECUTE),
        ]);
        let base = buf.as_ptr() as usize;
        // Exact 8-byte match selects the second section.
        let s = find_section(base, b".text$mn").unwrap();
        assert_eq!(s.virtual_address, base + 0x310);
    }

    // -- text_section_bounds (legacy wrapper over find_section) ---------

    #[test]
    fn text_section_bounds_finds_text() {
        let body = [0x90u8, 0xC3];
        let buf = synthetic_pe(&[(*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE)]);
        let base = buf.as_ptr() as usize;
        let (start, size) = text_section_bounds(base).unwrap();
        assert_eq!(start, base + 0x300);
        assert_eq!(size, body.len());
    }

    #[test]
    fn text_section_bounds_rejects_missing_mz() {
        let buf = vec![0u8; 0x400];
        assert!(text_section_bounds(buf.as_ptr() as usize).is_none());
    }

    #[test]
    fn text_section_bounds_rejects_missing_pe_sig() {
        let mut buf = vec![0u8; 0x400];
        buf[0] = b'M';
        buf[1] = b'Z';
        let nt_offset: u32 = 0x80;
        buf[0x3C..0x40].copy_from_slice(&nt_offset.to_le_bytes());
        assert!(text_section_bounds(buf.as_ptr() as usize).is_none());
    }

    #[test]
    fn text_section_bounds_skips_non_text_sections() {
        let data_body = [0xAAu8, 0xBB];
        let text_body = [0x90u8, 0xC3];
        let buf = synthetic_pe(&[
            (*b".data\0\0\0", 0x300, &data_body, 0),
            (*b".text\0\0\0", 0x310, &text_body, IMAGE_SCN_MEM_EXECUTE),
        ]);
        let base = buf.as_ptr() as usize;
        let (start, size) = text_section_bounds(base).unwrap();
        assert_eq!(start, base + 0x310);
        assert_eq!(size, text_body.len());
    }

    #[test]
    fn text_section_bounds_returns_none_when_no_text() {
        let body = [0xAAu8, 0xBB];
        let buf = synthetic_pe(&[(*b".data\0\0\0", 0x300, &body, 0)]);
        assert!(text_section_bounds(buf.as_ptr() as usize).is_none());
    }

    // -- exec_sections (legacy wrapper over iter_sections) ----------------

    #[test]
    fn exec_sections_includes_only_executable() {
        let exec_body = [0x90u8, 0xC3];
        let data_body = [0xAAu8, 0xBB];
        let buf = synthetic_pe(&[
            (*b".text\0\0\0", 0x300, &exec_body, IMAGE_SCN_MEM_EXECUTE),
            (*b".data\0\0\0", 0x310, &data_body, 0),
        ]);
        let base = buf.as_ptr() as usize;
        let secs = exec_sections(base).unwrap();
        assert_eq!(secs.len(), 1);
        assert_eq!(secs[0], (base + 0x300, exec_body.len()));
    }

    #[test]
    fn exec_sections_returns_multiple_when_multiple_exec() {
        let body_a = [0x90u8];
        let body_b = [0xC3u8];
        let buf = synthetic_pe(&[
            (*b".text\0\0\0", 0x300, &body_a, IMAGE_SCN_MEM_EXECUTE),
            (*b".text$mn", 0x310, &body_b, IMAGE_SCN_MEM_EXECUTE),
        ]);
        let base = buf.as_ptr() as usize;
        let secs = exec_sections(base).unwrap();
        assert_eq!(secs.len(), 2);
        assert_eq!(secs[0], (base + 0x300, body_a.len()));
        assert_eq!(secs[1], (base + 0x310, body_b.len()));
    }

    #[test]
    fn exec_sections_rejects_missing_mz() {
        let buf = vec![0u8; 0x400];
        assert!(exec_sections(buf.as_ptr() as usize).is_none());
    }

    #[test]
    fn exec_sections_rejects_missing_pe_sig() {
        let mut buf = vec![0u8; 0x400];
        buf[0] = b'M';
        buf[1] = b'Z';
        let nt_offset: u32 = 0x80;
        buf[0x3C..0x40].copy_from_slice(&nt_offset.to_le_bytes());
        assert!(exec_sections(buf.as_ptr() as usize).is_none());
    }

    #[test]
    fn exec_sections_empty_when_no_exec_sections() {
        let body = [0xAAu8];
        let buf = synthetic_pe(&[(*b".data\0\0\0", 0x300, &body, 0)]);
        let secs = exec_sections(buf.as_ptr() as usize).unwrap();
        assert!(secs.is_empty());
    }

    // -- module_size (feature `section-info`) ----------------------------

    #[cfg(feature = "section-info")]
    mod module_size_tests {
        use super::synthetic_pe;
        use crate::pe::{module_size, IMAGE_SCN_MEM_EXECUTE};
        use alloc::vec;

        #[test]
        fn returns_size_of_image() {
            let body = [0x90u8, 0xC3];
            let buf = synthetic_pe(&[(*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE)]);
            let base = buf.as_ptr() as usize;
            // synthetic_pe writes SizeOfImage = buf.len().
            assert_eq!(module_size(base), Some(buf.len()));
        }

        #[test]
        fn rejects_zero_base() {
            assert_eq!(module_size(0), None);
        }

        #[test]
        fn rejects_missing_mz() {
            let buf = vec![0u8; 0x400];
            assert!(module_size(buf.as_ptr() as usize).is_none());
        }

        #[test]
        fn rejects_missing_pe_sig() {
            let mut buf = vec![0u8; 0x400];
            buf[0] = b'M';
            buf[1] = b'Z';
            let nt_offset: u32 = 0x80;
            buf[0x3C..0x40].copy_from_slice(&nt_offset.to_le_bytes());
            assert!(module_size(buf.as_ptr() as usize).is_none());
        }

        /// Read what we actually planted, not what `buf.len()` happens
        /// to be. Catches off-by-one regressions in
        /// `OPTIONAL_HEADER_SIZE_OF_IMAGE_OFFSET` that the
        /// `returns_size_of_image` test wouldn't because the helper
        /// writes the field at the same offset the reader uses.
        #[test]
        fn reads_actual_size_of_image_field() {
            let body = [0x90u8];
            let mut buf = synthetic_pe(&[(*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE)]);
            // OptionalHeader.SizeOfImage at NT + 24 + 56 (= 0x80 + 80).
            let soi_offset = 0x80 + 4 + 20 + 56;
            let sentinel: u32 = 0xDEAD_BEEF;
            buf[soi_offset..soi_offset + 4].copy_from_slice(&sentinel.to_le_bytes());
            let base = buf.as_ptr() as usize;
            assert_eq!(module_size(base), Some(0xDEAD_BEEF));
        }

        /// Exercise the re-exported public path
        /// (`pe_sigscan::module_size`) so coverage tools that track
        /// import resolution see it called via the user-facing
        /// surface, not just the internal `crate::pe::module_size`.
        #[test]
        fn callable_via_public_re_export() {
            let body = [0x90u8];
            let buf = synthetic_pe(&[(*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE)]);
            let base = buf.as_ptr() as usize;
            assert_eq!(crate::module_size(base), Some(buf.len()));
        }
    }
}
