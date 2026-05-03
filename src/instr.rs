//! Helpers for resolving 32-bit relative displacements (`rel32`) embedded
//! inside matched x64 instructions to absolute target addresses.
//!
//! After locating an instruction with [`crate::find_in_text`] (or one of
//! its siblings), the next step in nearly every reverse-engineering /
//! game-mod workflow is "follow the displacement to its target". x64
//! encodes RIP-relative addresses as a signed 32-bit offset from the
//! address of the byte _immediately following_ the instruction, so the
//! arithmetic is small but easy to get wrong by an off-by-one. These
//! helpers package the calculation behind a single call site.
//!
//! ## Common instruction shapes
//!
//! | Instruction          | Bytes (anchor + disp)        | `rel32_offset` | `instr_len` |
//! | -------------------- | ---------------------------- | -------------- | ----------- |
//! | `mov rax, [rip+d32]` | `48 8B 05 ?? ?? ?? ??`       | 3              | 7           |
//! | `lea rax, [rip+d32]` | `48 8D 05 ?? ?? ?? ??`       | 3              | 7           |
//! | `call rel32`         | `E8 ?? ?? ?? ??`             | 1              | 5           |
//! | `jmp rel32`          | `E9 ?? ?? ?? ??`             | 1              | 5           |
//! | `jcc rel32`          | `0F 8x ?? ?? ?? ??`          | 2              | 6           |
//!
//! ## Example
//!
//! ```no_run
//! use pe_sigscan::{find_in_text, pattern, resolve_rel32_at};
//! # let module_base = 0usize;
//!
//! // mov rax, [rip+disp32]: 48 8B 05 ?? ?? ?? ?? (7 bytes total).
//! const SIG: &[Option<u8>] = pattern![0x48, 0x8B, 0x05, _, _, _, _];
//!
//! if let Some(addr) = find_in_text(module_base, SIG) {
//!     // Resolve the displacement to its target absolute address.
//!     let target = unsafe { resolve_rel32_at(addr, 3, 7) };
//!     println!("global at {target:#x}");
//! }
//! ```

/// Read a signed 32-bit displacement at `rel32_addr` and add it to
/// `next_ip` to produce an absolute target address.
///
/// `next_ip` is the value of RIP at the point the CPU performs the
/// addition — i.e. the address of the byte immediately after the matched
/// instruction.
///
/// The displacement read uses [`core::ptr::read_unaligned`] because
/// RIP-relative displacements are not architecturally guaranteed to be
/// 4-byte aligned (the matched instruction's start address has no
/// alignment requirement, and the displacement is at a fixed byte offset
/// inside the instruction).
///
/// Most callers will prefer the higher-level [`resolve_rel32_at`].
///
/// # Examples
///
/// ```no_run
/// use pe_sigscan::{find_in_text, pattern, resolve_rel32};
/// # let module_base = 0usize;
///
/// // mov rax, [rip+disp32]: 48 8B 05 ?? ?? ?? ??  (7 bytes total).
/// const SIG: &[Option<u8>] = pattern![0x48, 0x8B, 0x05, _, _, _, _];
/// if let Some(match_addr) = find_in_text(module_base, SIG) {
///     // Displacement bytes start at match_addr + 3, instruction is 7 bytes.
///     let target = unsafe { resolve_rel32(match_addr + 3, match_addr + 7) };
///     println!("dereferenced global at {target:#x}");
/// }
/// ```
///
/// # Safety
///
/// `[rel32_addr, rel32_addr + 4)` must be readable for the duration of
/// the call. For matches returned by the in-process scanners this is
/// guaranteed by the PE section bounds; the caller is responsible only
/// for ensuring the offsets stay within the matched pattern's length.
#[must_use]
#[inline]
pub unsafe fn resolve_rel32(rel32_addr: usize, next_ip: usize) -> usize {
    // RIP-relative displacements are not guaranteed 4-byte aligned, so
    // we go through `read_unaligned`. The compiler turns this into a
    // single MOV on x86_64 / aarch64 — there is no perf penalty.
    let disp = core::ptr::read_unaligned(rel32_addr as *const i32) as isize;
    (next_ip as isize).wrapping_add(disp) as usize
}

/// Convenience wrapper over [`resolve_rel32`] for the typical workflow:
/// you have a `match_addr` from `find_in_text`, and you know the byte
/// offset of the displacement inside the matched instruction
/// (`rel32_offset`) and the total length of the instruction
/// (`instr_len`).
///
/// Equivalent to:
///
/// ```ignore
/// resolve_rel32(match_addr + rel32_offset, match_addr + instr_len)
/// ```
///
/// See the table at the top of this module for `rel32_offset` / `instr_len`
/// values for the most common x64 instruction shapes.
///
/// # Examples
///
/// ```no_run
/// use pe_sigscan::{find_in_text, pattern, resolve_rel32_at};
/// # let module_base = 0usize;
///
/// // call rel32: E8 ?? ?? ?? ?? — disp at +1, total length 5.
/// const CALL_SIG: &[Option<u8>] = pattern![0xE8, _, _, _, _];
/// if let Some(addr) = find_in_text(module_base, CALL_SIG) {
///     let target = unsafe { resolve_rel32_at(addr, 1, 5) };
///     println!("call target: {target:#x}");
/// }
/// ```
///
/// # Safety
///
/// `[match_addr + rel32_offset, match_addr + rel32_offset + 4)` must be
/// readable. In practice, `rel32_offset + 4 <= instr_len`, so any pattern
/// whose length covers the full instruction satisfies this trivially.
#[must_use]
#[inline]
pub unsafe fn resolve_rel32_at(match_addr: usize, rel32_offset: usize, instr_len: usize) -> usize {
    resolve_rel32(match_addr + rel32_offset, match_addr + instr_len)
}

/// Read a little-endian signed 32-bit displacement from a byte slice.
///
/// Returns `None` if `offset + 4` would read past the end of `bytes`.
/// This is the safe slice counterpart to [`resolve_rel32`], suitable for
/// offline analysis pipelines that scan pre-extracted byte buffers and do
/// the absolute-address arithmetic in user code (where the choice of
/// "base" depends on whether you're modelling a loaded module, a section
/// from a dump, or a relocated buffer).
///
/// # Examples
///
/// ```
/// use pe_sigscan::read_rel32;
///
/// // Suppose `bytes[1..5]` is a `disp32` field equal to 0x10 (= 16).
/// let bytes = [0xAA, 0x10, 0x00, 0x00, 0x00];
/// assert_eq!(read_rel32(&bytes, 1), Some(16));
///
/// // Negative displacement (back-reference).
/// let neg = [0xE8, 0xFB, 0xFF, 0xFF, 0xFF]; // call rel32 = -5
/// assert_eq!(read_rel32(&neg, 1), Some(-5));
///
/// // Out-of-bounds offset returns None instead of panicking.
/// assert_eq!(read_rel32(&bytes, 3), None);
/// ```
#[must_use]
#[inline]
pub fn read_rel32(bytes: &[u8], offset: usize) -> Option<i32> {
    let end = offset.checked_add(4)?;
    let slice = bytes.get(offset..end)?;
    // `slice.len() == 4` is guaranteed by the `get` above, so the
    // `try_into` is infallible — but we propagate the error type rather
    // than panicking just in case a future refactor changes that.
    let arr: [u8; 4] = slice.try_into().ok()?;
    Some(i32::from_le_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- read_rel32 (safe slice helper) -----------------------------------

    #[test]
    fn read_rel32_basic_positive() {
        let bytes = [0xAA, 0x10, 0x00, 0x00, 0x00];
        assert_eq!(read_rel32(&bytes, 1), Some(16));
    }

    #[test]
    fn read_rel32_negative_displacement() {
        // call rel32 with a -5 displacement (a self-loop).
        let bytes = [0xE8, 0xFB, 0xFF, 0xFF, 0xFF];
        assert_eq!(read_rel32(&bytes, 1), Some(-5));
    }

    #[test]
    fn read_rel32_at_zero_offset() {
        let bytes = [0x78, 0x56, 0x34, 0x12];
        assert_eq!(read_rel32(&bytes, 0), Some(0x1234_5678));
    }

    #[test]
    fn read_rel32_out_of_bounds_returns_none() {
        let bytes = [0x00, 0x01, 0x02];
        // offset + 4 > len → None
        assert_eq!(read_rel32(&bytes, 0), None);
    }

    #[test]
    fn read_rel32_offset_at_exact_end_returns_none() {
        let bytes = [0x00, 0x01, 0x02, 0x03];
        // offset == len → empty slice → too short for 4 bytes.
        assert_eq!(read_rel32(&bytes, 4), None);
    }

    #[test]
    fn read_rel32_offset_overflow_returns_none() {
        // offset.checked_add(4) overflows → None, not panic.
        let bytes = [0x00; 16];
        assert_eq!(read_rel32(&bytes, usize::MAX - 2), None);
    }

    #[test]
    fn read_rel32_empty_slice_returns_none() {
        assert_eq!(read_rel32(&[], 0), None);
    }

    // -- resolve_rel32 (raw, unsafe) --------------------------------------

    /// Build a buffer that mimics a `mov rax, [rip+disp32]` (48 8B 05
    /// disp32) instruction at known address, then verify
    /// `resolve_rel32` resolves the displacement correctly.
    #[test]
    fn resolve_rel32_mov_rip_relative() {
        // `mov rax, [rip+0x10]` → 48 8B 05 10 00 00 00.
        let buf: [u8; 7] = [0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00];
        let match_addr = buf.as_ptr() as usize;
        let target = unsafe { resolve_rel32(match_addr + 3, match_addr + 7) };
        // next_ip = match_addr + 7; disp = +0x10. Target = match_addr + 7 + 0x10.
        assert_eq!(target, match_addr + 7 + 0x10);
    }

    #[test]
    fn resolve_rel32_negative_displacement() {
        // call rel32 = -0x10 → E8 F0 FF FF FF.
        let buf: [u8; 5] = [0xE8, 0xF0, 0xFF, 0xFF, 0xFF];
        let match_addr = buf.as_ptr() as usize;
        let target = unsafe { resolve_rel32(match_addr + 1, match_addr + 5) };
        // next_ip = match_addr + 5; disp = -0x10. Target = match_addr - 0xB.
        assert_eq!(target, match_addr.wrapping_sub(0x0B));
    }

    #[test]
    fn resolve_rel32_zero_displacement() {
        // disp32 = 0 → target == next_ip.
        let buf: [u8; 5] = [0xE9, 0x00, 0x00, 0x00, 0x00];
        let match_addr = buf.as_ptr() as usize;
        let target = unsafe { resolve_rel32(match_addr + 1, match_addr + 5) };
        assert_eq!(target, match_addr + 5);
    }

    #[test]
    fn resolve_rel32_unaligned_read_ok() {
        // Place the disp32 at an odd offset in a larger buffer to make
        // sure `read_unaligned` doesn't blow up on misalignment.
        let mut buf = [0u8; 16];
        buf[5] = 0x78;
        buf[6] = 0x56;
        buf[7] = 0x34;
        buf[8] = 0x12;
        let base = buf.as_ptr() as usize;
        let target = unsafe { resolve_rel32(base + 5, base + 9) };
        // next_ip = base + 9; disp = 0x12345678.
        assert_eq!(target, (base + 9).wrapping_add(0x1234_5678));
    }

    // -- resolve_rel32_at (convenience over resolve_rel32) ----------------

    #[test]
    fn resolve_rel32_at_matches_resolve_rel32() {
        // Both must produce the same result for the same logical inputs.
        let buf: [u8; 7] = [0x48, 0x8D, 0x05, 0x21, 0x43, 0x65, 0x07];
        let match_addr = buf.as_ptr() as usize;
        let a = unsafe { resolve_rel32(match_addr + 3, match_addr + 7) };
        let b = unsafe { resolve_rel32_at(match_addr, 3, 7) };
        assert_eq!(a, b);
    }

    #[test]
    fn resolve_rel32_at_call_instruction() {
        // call rel32 with displacement +0x40000000.
        let buf: [u8; 5] = [0xE8, 0x00, 0x00, 0x00, 0x40];
        let match_addr = buf.as_ptr() as usize;
        let target = unsafe { resolve_rel32_at(match_addr, 1, 5) };
        assert_eq!(target, (match_addr + 5).wrapping_add(0x4000_0000));
    }
}
