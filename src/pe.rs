//! Internal PE (Portable Executable) header walking.
//!
//! All public scanning entry points funnel through this module to translate
//! a `module_base: usize` into one or more `(virtual_address_absolute,
//! virtual_size)` ranges that are guaranteed readable. The PE format is
//! fixed by the Windows loader, so this module is a straight transcription
//! of the relevant header offsets — no heuristics.
//!
//! Nothing here is part of the public API.

use alloc::vec::Vec;
use core::slice;

/// `IMAGE_SCN_MEM_EXECUTE` — section can be executed as code. Set for
/// `.text` and any companion code sections (e.g. `.text$mn`, `.textbss`,
/// jump-table arenas, optimised-layout sections that some compilers and
/// linkers emit).
pub(crate) const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

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

/// Walk the PE section table at `module_base` and return every section
/// whose characteristics include `IMAGE_SCN_MEM_EXECUTE` as
/// `(virtual_address_absolute, virtual_size)` pairs.
///
/// Returns `None` if the headers are malformed; an empty `Vec` is possible
/// if the module has no executable sections (shouldn't happen for a code
/// DLL, but is handled cleanly).
pub(crate) fn exec_sections(module_base: usize) -> Option<Vec<(usize, usize)>> {
    // SAFETY: see `text_section_bounds` for the validation contract. The
    // first byte read confirms the MZ signature; if `module_base` ever
    // points at unmapped or non-PE memory, the magic check fails and we
    // return None before any out-of-bounds read.
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

        let mut out = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let sec = section_table + i * SECTION_HEADER_SIZE;
            // IMAGE_SECTION_HEADER:
            //   +8:  VirtualSize (u32)
            //   +12: VirtualAddress (u32)
            //   +36: Characteristics (u32)
            let virtual_size = *((sec + 8) as *const u32) as usize;
            let virtual_address = *((sec + 12) as *const u32) as usize;
            let characteristics = *((sec + 36) as *const u32);
            if (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 {
                out.push((module_base + virtual_address, virtual_size));
            }
        }
        Some(out)
    }
}

/// Parse the PE headers at `module_base` and return the `.text` section's
/// `(virtual_address_absolute, virtual_size)` tuple.
///
/// Returns `None` if the headers are malformed or `.text` isn't found.
pub(crate) fn text_section_bounds(module_base: usize) -> Option<(usize, usize)> {
    // SAFETY: All reads below are bounded against the immediately preceding
    // length fields and against the PE header layout, which is fixed by the
    // Windows loader. The first byte read confirms the MZ signature; if
    // `module_base` ever points at unmapped or non-PE memory, the magic
    // check fails and we return None before any out-of-bounds read.
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

        for i in 0..num_sections {
            let sec = section_table + i * SECTION_HEADER_SIZE;
            // IMAGE_SECTION_HEADER.Name (8 bytes ASCII at +0).
            let name = slice::from_raw_parts(sec as *const u8, 8);
            // ".text\0\0\0" is what MSVC emits; the leading 5 bytes are
            // stable across compilers.
            if name.starts_with(b".text") {
                let virtual_size = *((sec + 8) as *const u32) as usize;
                let virtual_address = *((sec + 12) as *const u32) as usize;
                return Some((module_base + virtual_address, virtual_size));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    /// Build a minimal PE-shaped byte buffer with a configurable section
    /// list. Each entry is `(name_8b, virtual_address, text_bytes,
    /// characteristics)`. Returns the buffer; the section payload bytes are
    /// copied into the buffer at each section's declared
    /// `virtual_address`.
    ///
    /// This is intentionally barebones — it is NOT a valid loadable PE;
    /// only the fields the parser reads are populated. Sufficient to drive
    /// every branch in the PE-walking code from a unit test without needing
    /// a real DLL on disk.
    pub(super) fn synthetic_pe(sections: &[([u8; 8], u32, &[u8], u32)]) -> Vec<u8> {
        // Layout the buffer big enough that every section's
        // `virtual_address + size` fits.
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
        // Buffer with no MZ signature — first u16 is zero.
        let buf = vec![0u8; 0x400];
        assert!(text_section_bounds(buf.as_ptr() as usize).is_none());
    }

    #[test]
    fn text_section_bounds_rejects_missing_pe_sig() {
        let mut buf = vec![0u8; 0x400];
        // Plant MZ but leave NT signature as zero (passes magic check, fails
        // the NT signature check below).
        buf[0] = b'M';
        buf[1] = b'Z';
        let nt_offset: u32 = 0x80;
        buf[0x3C..0x40].copy_from_slice(&nt_offset.to_le_bytes());
        // Don't write 'PE\0\0' at nt_offset → NT-sig check fails.
        assert!(text_section_bounds(buf.as_ptr() as usize).is_none());
    }

    #[test]
    fn text_section_bounds_skips_non_text_sections() {
        // A `.data` section first, then `.text` second. The walker should
        // skip the first and return the second.
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
        // Only a `.data` section, no `.text`.
        let body = [0xAAu8, 0xBB];
        let buf = synthetic_pe(&[(*b".data\0\0\0", 0x300, &body, 0)]);
        assert!(text_section_bounds(buf.as_ptr() as usize).is_none());
    }

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
        // Only the executable section is returned.
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
        // No PE signature.
        assert!(exec_sections(buf.as_ptr() as usize).is_none());
    }

    #[test]
    fn exec_sections_empty_when_no_exec_sections() {
        let body = [0xAAu8];
        let buf = synthetic_pe(&[(*b".data\0\0\0", 0x300, &body, 0)]);
        let secs = exec_sections(buf.as_ptr() as usize).unwrap();
        assert!(secs.is_empty());
    }
}
