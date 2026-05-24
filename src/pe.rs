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

use crate::MemoryReader;

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

/// Raw 8-byte `.text` section name (`IMAGE_SECTION_HEADER.Name`).
const SECTION_NAME_TEXT: &[u8; 8] = b".text\0\0\0";

/// `IMAGE_DOS_HEADER.e_lfanew` byte offset — file offset of NT headers.
const DOS_E_LFANEW_OFFSET: usize = 0x3C;

/// Size of `IMAGE_FILE_HEADER` in bytes.
const FILE_HEADER_SIZE: usize = 20;

/// Size of one `IMAGE_SECTION_HEADER` entry.
const SECTION_HEADER_SIZE: usize = 40;

/// Byte offset of the optional header relative to NT headers
/// (`Signature` u32 + `IMAGE_FILE_HEADER` 20 bytes).
const OPTIONAL_HEADER_OFFSET: usize = 4 + FILE_HEADER_SIZE;

/// Byte offset of `IMAGE_OPTIONAL_HEADER.SizeOfImage` *within the
/// optional header*. PE32 and PE32+ both place this field at +56,
/// despite their preceding fields differing in width
/// (`ImageBase` is `u32` in PE32 and `u64` in PE32+; `BaseOfData`
/// is PE32-only). Because the totals come out the same, we can
/// read `SizeOfImage` without distinguishing the two formats.
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
    nt: usize,
    /// Absolute address of the first `IMAGE_SECTION_HEADER` entry.
    section_table: usize,
    /// `IMAGE_FILE_HEADER.NumberOfSections`.
    num_sections: usize,
}

// SAFETY: Guess it, I'm tired of writing "the caller must ensure..." on every unsafe function.
#[inline]
unsafe fn read_u16_unaligned(addr: usize) -> u16 {
    core::ptr::read_unaligned(addr as *const u16)
}

// SAFETY: Guess it, I'm tired of writing "the caller must ensure..." on every unsafe function.
#[inline]
unsafe fn read_u32_unaligned(addr: usize) -> u32 {
    core::ptr::read_unaligned(addr as *const u32)
}

#[inline]
fn parse_pe_headers(module_base: usize) -> Option<PeHeaders> {
    if module_base == 0 {
        return None;
    }
    // SAFETY: the MZ + PE magic checks gate every subsequent read.
    // If `module_base` doesn't point at a real PE, one of those
    // checks fails and we return None before any further deref.
    unsafe {
        if read_u16_unaligned(module_base) != DOS_MAGIC_MZ {
            return None;
        }
        let nt_offset = read_u32_unaligned(module_base + DOS_E_LFANEW_OFFSET) as usize;
        let nt = module_base.checked_add(nt_offset)?;
        if read_u32_unaligned(nt) != NT_SIGNATURE_PE {
            return None;
        }
        let file_hdr = nt.checked_add(4)?;
        let num_sections = read_u16_unaligned(file_hdr + 2) as usize;
        let opt_hdr_size = read_u16_unaligned(file_hdr + 16) as usize;
        let section_table = file_hdr.checked_add(FILE_HEADER_SIZE + opt_hdr_size)?;
        Some(PeHeaders {
            module_base,
            nt,
            section_table,
            num_sections,
        })
    }
}

#[inline]
fn read_u16_with<R: MemoryReader>(reader: &R, addr: usize) -> Option<u16> {
    let mut buf = [0u8; 2];
    reader.read_bytes(addr, &mut buf)?;
    Some(u16::from_le_bytes(buf))
}

#[inline]
fn read_u32_with<R: MemoryReader>(reader: &R, addr: usize) -> Option<u32> {
    let mut buf = [0u8; 4];
    reader.read_bytes(addr, &mut buf)?;
    Some(u32::from_le_bytes(buf))
}

#[inline]
fn parse_pe_headers_with<R: MemoryReader>(reader: &R, module_base: usize) -> Option<PeHeaders> {
    if module_base == 0 {
        return None;
    }
    if read_u16_with(reader, module_base)? != DOS_MAGIC_MZ {
        return None;
    }
    let nt_offset = read_u32_with(reader, module_base + DOS_E_LFANEW_OFFSET)? as usize;
    let nt = module_base.checked_add(nt_offset)?;
    if read_u32_with(reader, nt)? != NT_SIGNATURE_PE {
        return None;
    }
    let file_hdr = nt.checked_add(4)?;
    let num_sections = read_u16_with(reader, file_hdr + 2)? as usize;
    let opt_hdr_size = read_u16_with(reader, file_hdr + 16)? as usize;
    let section_table = file_hdr.checked_add(FILE_HEADER_SIZE + opt_hdr_size)?;
    Some(PeHeaders {
        module_base,
        nt,
        section_table,
        num_sections,
    })
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
    let virtual_size = read_u32_unaligned(sec + 8) as usize;
    let virtual_address = read_u32_unaligned(sec + 12) as usize;
    let characteristics = read_u32_unaligned(sec + 36);
    SectionInfo {
        name,
        virtual_address: module_base + virtual_address,
        virtual_size,
        characteristics,
    }
}

#[inline]
fn read_section_at_with<R: MemoryReader>(
    reader: &R,
    sec: usize,
    module_base: usize,
) -> Option<SectionInfo> {
    let mut header = [0u8; SECTION_HEADER_SIZE];
    reader.read_bytes(sec, &mut header)?;

    let mut name = [0u8; 8];
    name.copy_from_slice(&header[..8]);

    let virtual_size = u32::from_le_bytes([header[8], header[9], header[10], header[11]]) as usize;
    let virtual_address =
        u32::from_le_bytes([header[12], header[13], header[14], header[15]]) as usize;
    let characteristics = u32::from_le_bytes([header[36], header[37], header[38], header[39]]);

    Some(SectionInfo {
        name,
        virtual_address: module_base + virtual_address,
        virtual_size,
        characteristics,
    })
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

pub(crate) fn iter_sections_with<R: MemoryReader>(
    reader: &R,
    module_base: usize,
) -> Option<Vec<SectionInfo>> {
    let hdr = parse_pe_headers_with(reader, module_base)?;
    let mut sections = Vec::with_capacity(hdr.num_sections);
    for i in 0..hdr.num_sections {
        let sec = hdr.section_table + i * SECTION_HEADER_SIZE;
        sections.push(read_section_at_with(reader, sec, hdr.module_base)?);
    }
    Some(sections)
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

pub(crate) fn find_section_with<R: MemoryReader>(
    reader: &R,
    module_base: usize,
    prefix: &[u8],
) -> Option<SectionInfo> {
    iter_sections_with(reader, module_base)?
        .into_iter()
        .find(|section| section.name.starts_with(prefix))
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

pub(crate) fn exec_sections_with<R: MemoryReader>(
    reader: &R,
    module_base: usize,
) -> Option<Vec<(usize, usize)>> {
    Some(
        iter_sections_with(reader, module_base)?
            .into_iter()
            .filter(SectionInfo::is_executable)
            .map(|section| (section.virtual_address, section.virtual_size))
            .collect(),
    )
}

/// Return the `.text` section's `(virtual_address_absolute,
/// virtual_size)` tuple, or `None` if the headers are malformed or
/// `.text` is missing.
pub(crate) fn text_section_bounds(module_base: usize) -> Option<(usize, usize)> {
    let s = find_section(module_base, SECTION_NAME_TEXT)?;
    Some((s.virtual_address, s.virtual_size))
}

pub(crate) fn text_section_bounds_with<R: MemoryReader>(
    reader: &R,
    module_base: usize,
) -> Option<(usize, usize)> {
    let section = find_section_with(reader, module_base, SECTION_NAME_TEXT)?;
    Some((section.virtual_address, section.virtual_size))
}

// ---------------------------------------------------------------------------
// module_size (always available)
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
#[must_use]
pub fn module_size(module_base: usize) -> Option<usize> {
    let hdr = parse_pe_headers(module_base)?;
    // SAFETY: `hdr.nt` was validated against the PE signature.
    // SizeOfImage is at OptionalHeader+56, same offset in PE32 and
    // PE32+ — well inside the loader-mapped header region.
    unsafe {
        let size_of_image_addr = hdr
            .nt
            .checked_add(OPTIONAL_HEADER_OFFSET + OPTIONAL_HEADER_SIZE_OF_IMAGE_OFFSET)?;
        Some(read_u32_unaligned(size_of_image_addr) as usize)
    }
}

/// Read `IMAGE_OPTIONAL_HEADER.SizeOfImage` through a [`MemoryReader`].
///
/// This is the out-of-process companion to [`module_size`].
#[must_use]
pub fn module_size_with<R: MemoryReader>(reader: &R, module_base: usize) -> Option<usize> {
    let hdr = parse_pe_headers_with(reader, module_base)?;
    let size_of_image_addr = hdr
        .nt
        .checked_add(OPTIONAL_HEADER_OFFSET + OPTIONAL_HEADER_SIZE_OF_IMAGE_OFFSET)?;
    Some(read_u32_with(reader, size_of_image_addr)? as usize)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryReader;
    use alloc::vec;
    use alloc::vec::Vec;

    struct SliceReader {
        base: usize,
        bytes: Vec<u8>,
    }

    impl MemoryReader for SliceReader {
        fn read_bytes(&self, addr: usize, buf: &mut [u8]) -> Option<()> {
            let start = addr.checked_sub(self.base)?;
            let end = start.checked_add(buf.len())?;
            if end > self.bytes.len() {
                return None;
            }
            buf.copy_from_slice(&self.bytes[start..end]);
            Some(())
        }
    }

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

    #[test]
    fn parse_pe_headers_accepts_unaligned_module_base() {
        let body = [0x90u8];
        let image = synthetic_pe(&[(*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE)]);
        let mut backing = vec![0u8; image.len() + 1];
        backing[1..].copy_from_slice(&image);

        let base = backing.as_ptr() as usize + 1;
        let hdr = parse_pe_headers(base).unwrap();
        assert_eq!(hdr.module_base, base);
        assert_eq!(hdr.section_table, base + 0x80 + 24 + 0xF0);
    }

    #[test]
    fn parse_pe_headers_with_returns_none_for_zero_base() {
        let reader = SliceReader {
            base: 0x5000_0000,
            bytes: vec![0u8; 0x400],
        };
        assert!(parse_pe_headers_with(&reader, 0).is_none());
    }

    #[test]
    fn parse_pe_headers_with_returns_none_for_missing_mz() {
        let reader = SliceReader {
            base: 0x5000_0000,
            bytes: vec![0u8; 0x400],
        };
        assert!(parse_pe_headers_with(&reader, reader.base).is_none());
    }

    #[test]
    fn parse_pe_headers_with_returns_none_for_short_dos_header() {
        let reader = SliceReader {
            base: 0x5000_0000,
            bytes: vec![b'M', b'Z'],
        };
        assert!(parse_pe_headers_with(&reader, reader.base).is_none());
    }

    #[test]
    fn parse_pe_headers_with_returns_none_for_missing_pe_sig() {
        let mut bytes = vec![0u8; 0x400];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        let nt_offset: u32 = 0x80;
        bytes[0x3C..0x40].copy_from_slice(&nt_offset.to_le_bytes());
        let reader = SliceReader {
            base: 0x5000_0000,
            bytes,
        };
        assert!(parse_pe_headers_with(&reader, reader.base).is_none());
    }

    #[test]
    fn parse_pe_headers_with_walks_to_section_table() {
        let body = [0x90u8];
        let reader = SliceReader {
            base: 0x5000_0000,
            bytes: synthetic_pe(&[(*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE)]),
        };
        let hdr = parse_pe_headers_with(&reader, reader.base).unwrap();
        assert_eq!(hdr.num_sections, 1);
        assert_eq!(hdr.module_base, reader.base);
        assert_eq!(hdr.section_table, reader.base + 0x80 + 24 + 0xF0);
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

    #[test]
    fn text_section_bounds_prefers_exact_text_over_prefixed_text_sections() {
        let prefixed_body = [0x11u8, 0x22];
        let text_body = [0xAAu8, 0xBB, 0xCC];
        let buf = synthetic_pe(&[
            (*b".text$mn", 0x300, &prefixed_body, IMAGE_SCN_MEM_EXECUTE),
            (*SECTION_NAME_TEXT, 0x400, &text_body, IMAGE_SCN_MEM_EXECUTE),
        ]);
        let base = buf.as_ptr() as usize;

        assert_eq!(text_section_bounds(base), Some((base + 0x400, text_body.len())));
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

    #[test]
    fn iter_sections_with_and_helpers_work_for_remote_reader() {
        let exec_body = [0x90u8, 0xC3];
        let data_body = [0xAAu8, 0xBB];
        let reader = SliceReader {
            base: 0x5000_0000,
            bytes: synthetic_pe(&[
                (*b".text\0\0\0", 0x300, &exec_body, IMAGE_SCN_MEM_EXECUTE),
                (*b".data\0\0\0", 0x310, &data_body, IMAGE_SCN_MEM_READ),
            ]),
        };

        let sections = iter_sections_with(&reader, reader.base).unwrap();
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].virtual_address, reader.base + 0x300);
        assert_eq!(
            find_section_with(&reader, reader.base, b".text")
                .unwrap()
                .virtual_address,
            reader.base + 0x300,
        );
        assert_eq!(
            text_section_bounds_with(&reader, reader.base),
            Some((reader.base + 0x300, exec_body.len())),
        );
        assert_eq!(
            exec_sections_with(&reader, reader.base),
            Some(vec![(reader.base + 0x300, exec_body.len())]),
        );
    }

    #[test]
    fn iter_sections_with_returns_none_when_section_header_read_fails() {
        let body = [0x90u8];
        let mut bytes = synthetic_pe(&[(*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE)]);
        bytes.truncate(0x188 + 39);
        let reader = SliceReader {
            base: 0x5000_0000,
            bytes,
        };

        assert!(iter_sections_with(&reader, reader.base).is_none());
        assert!(find_section_with(&reader, reader.base, b".text").is_none());
        assert!(text_section_bounds_with(&reader, reader.base).is_none());
        assert!(exec_sections_with(&reader, reader.base).is_none());
    }

    #[test]
    fn text_section_bounds_with_prefers_exact_text_over_prefixed_text_sections() {
        let prefixed_body = [0x11u8, 0x22];
        let text_body = [0xAAu8, 0xBB, 0xCC];
        let reader = SliceReader {
            base: 0x5000_0000,
            bytes: synthetic_pe(&[
                (*b".text$mn", 0x300, &prefixed_body, IMAGE_SCN_MEM_EXECUTE),
                (*SECTION_NAME_TEXT, 0x400, &text_body, IMAGE_SCN_MEM_EXECUTE),
            ]),
        };

        assert_eq!(
            text_section_bounds_with(&reader, reader.base),
            Some((reader.base + 0x400, text_body.len())),
        );
    }

    #[test]
    fn slice_reader_rejects_underflow_overflow_and_oob_reads() {
        let reader = SliceReader {
            base: 0x10,
            bytes: vec![0u8; 4],
        };
        let mut buf = [0u8; 2];

        assert!(reader.read_bytes(reader.base - 1, &mut buf).is_none());
        assert!(reader.read_bytes(reader.base + 3, &mut buf).is_none());

        let overflow_reader = SliceReader {
            base: 0,
            bytes: vec![0u8; 4],
        };
        assert!(overflow_reader.read_bytes(usize::MAX, &mut buf).is_none());
    }

    // -- module_size (feature `section-info`) ----------------------------

    #[cfg(feature = "section-info")]
    mod module_size_tests {
        use super::synthetic_pe;
        use crate::pe::{module_size, module_size_with, IMAGE_SCN_MEM_EXECUTE};
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

        #[test]
        fn reads_size_of_image_from_unaligned_module_base() {
            let body = [0x90u8];
            let image = synthetic_pe(&[(*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE)]);
            let mut backing = vec![0u8; image.len() + 1];
            backing[1..].copy_from_slice(&image);

            let base = backing.as_ptr() as usize + 1;
            assert_eq!(module_size(base), Some(image.len()));
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

        #[test]
        fn module_size_with_reads_remote_size_of_image() {
            let body = [0x90u8];
            let bytes = synthetic_pe(&[(*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE)]);
            let expected = bytes.len();
            let reader = super::SliceReader {
                base: 0x5000_0000,
                bytes,
            };
            assert_eq!(module_size_with(&reader, reader.base), Some(expected));
        }

        #[test]
        fn module_size_with_returns_none_when_size_of_image_read_is_truncated() {
            let body = [0x90u8];
            let mut bytes = synthetic_pe(&[(*b".text\0\0\0", 0x300, &body, IMAGE_SCN_MEM_EXECUTE)]);
            let size_of_image_offset = 0x80 + 24 + 56;
            bytes.truncate(size_of_image_offset + 3);
            let reader = super::SliceReader {
                base: 0x5000_0000,
                bytes,
            };

            assert!(module_size_with(&reader, reader.base).is_none());
        }
    }
}
