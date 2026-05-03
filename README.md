# pe-sigscan

[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![codecov](https://codecov.io/gh/H0llyW00dzZ/pe-sigscan/graph/badge.svg?token=16K4XYW1LB)](https://codecov.io/gh/H0llyW00dzZ/pe-sigscan)

<p align="center">
  <img src="assets/image/logo.jpg" alt="pe-sigscan logo" width="280">
</p>

Fast in-process byte-pattern ("signature") scanning over the executable
sections of a loaded PE module on Windows.

A small, dependency-free building block for game mods, hookers, debuggers, and
any other in-process tool that needs to locate non-exported, non-vtable-
accessible code by its byte signature.

## Features

- **IDA-style wildcard patterns**, parsed from a string at runtime
  (`Pattern::from_ida("48 8B 05 ?? ?? ?? ?? 48 89 41 08")`) or built at
  compile time with the `pattern!` macro (no allocation).
- **Two scanning modes**: walk only the section literally named `.text`, or
  walk every section whose `IMAGE_SCN_MEM_EXECUTE` characteristic is set
  (required for some compilers / linkers that split code into companion
  sections like `.text$mn`).
- **Hook-install uniqueness**: companion `count_*` functions let you verify
  a pattern matches exactly once before patching, so you never silently
  hook the wrong function.
- **Slice variants** (`find_in_slice`, `count_in_slice`) for offline
  analysis and unit testing without a loaded PE.
- **Direct memory reads** (no `ReadProcessMemory` round-trip per byte) —
  suitable for scanning tens of megabytes of `.text` in well under a
  second.
- **Vectorized first-byte search**. The hot anchor pre-filter ships in two
  flavours: a portable SWAR (8-byte word) implementation that is the
  default, and an optional `memchr`-backed path that uses runtime-detected
  AVX2 / SSE2 / NEON. See [Performance](#performance) for numbers.
- **`#![no_std]`-compatible**, allocates only when constructing an owned
  `Pattern` from an IDA-style string. The compile-time `pattern!` macro
  produces a `&'static [Option<u8>]` with zero allocation.
- **Zero dependencies by default.** Enabling the optional `memchr` feature
  pulls in a single SIMD-accelerated dependency.

## Quick start

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
pe-sigscan = "0.1"
```

Or, for SIMD-accelerated scans (recommended for cheats / mod loaders):

```toml
[dependencies]
pe-sigscan = { version = "0.1", features = ["memchr"] }
```

### Scanning the loaded process

```rust,no_run
use pe_sigscan::{find_in_text, Pattern};

// Get a module base via your preferred means (GetModuleHandleW, PEB walk, etc.).
let module_base: usize = /* ... */ 0;

// Build a pattern from an IDA-style hex string. `?` and `??` are wildcards.
let pat = Pattern::from_ida("48 8B 05 ?? ?? ?? ?? 48 89 41 08").unwrap();

if let Some(addr) = find_in_text(module_base, pat.as_slice()) {
    println!("matched at {addr:#x}");
}
```

### Compile-time patterns

```rust
use pe_sigscan::pattern;

// `_` is the wildcard token; bytes use 0xNN literals.
const SIG: &[Option<u8>] = pattern![0x48, 0x8B, _, _, 0x48, 0x89];
```

### Verifying uniqueness before installing a hook

```rust,no_run
use pe_sigscan::{count_in_text, find_in_text, pattern};
# let module_base: usize = 0;

const TARGET_SIG: &[Option<u8>] = pattern![
    0x48, 0x89, 0x5C, 0x24, _, 0x48, 0x89, 0x74, 0x24, _,
    0x48, 0x89, 0x7C, 0x24, _, 0x55, 0x41, 0x56, 0x41, 0x57,
];

let count = count_in_text(module_base, TARGET_SIG);
match count {
    1 => {
        let addr = find_in_text(module_base, TARGET_SIG).unwrap();
        // … install hook at `addr`
    }
    0 => panic!("pattern not found — game may have been updated"),
    n => panic!("pattern matched {n} sites — refusing to install (ambiguous)"),
}
```

### Walking every executable section

Some compilers and linkers split code into multiple sections (`.text$mn`,
`.textbss`, optimized-layout arenas). Use the `*_in_exec_sections` variants
when the function you're scanning for might not live in the section
literally named `.text`:

```rust,no_run
use pe_sigscan::{find_in_exec_sections, pattern};
# let module_base: usize = 0;

const SIG: &[Option<u8>] = pattern![0x48, 0x8B, _, _, _, _, 0xFF, 0xE0];
let addr = find_in_exec_sections(module_base, SIG);
```

### Offline analysis (no loaded PE required)

```rust
use pe_sigscan::{find_in_slice, pattern};

let bytes = [0x00, 0x11, 0x48, 0x8B, 0x05, 0x99];
let pat = pattern![0x48, 0x8B, 0x05];
let hit = find_in_slice(&bytes, pat).unwrap();
assert_eq!(hit, bytes.as_ptr() as usize + 2);
```

## Pattern syntax

`Pattern::from_ida` accepts whitespace-separated tokens:

| Token  | Meaning                                |
| ------ | -------------------------------------- |
| `XX`   | Two hex digits — match the literal byte `0xXX`. Case-insensitive. |
| `?`    | Wildcard — match any byte.             |
| `??`   | Wildcard (long form, identical to `?`). |

ASCII whitespace (spaces, tabs, newlines, carriage returns) between tokens is
ignored. Anything else returns a [`ParsePatternError`] with the offending
token's index.

```rust
use pe_sigscan::Pattern;
assert!(Pattern::from_ida("48 8B ?? 89").is_ok());
assert!(Pattern::from_ida("AB CD EF").is_ok());           // upper-case hex
assert!(Pattern::from_ida("ab cd ef").is_ok());           // lower-case hex
assert!(Pattern::from_ida("  48\t??\n89  ").is_ok());     // extra whitespace
assert!(Pattern::from_ida("48 ZZ 89").is_err());          // invalid hex
assert!(Pattern::from_ida("48 8 89").is_err());           // single hex digit
assert!(Pattern::from_ida("").is_err());                  // empty
```

## Performance

Signature scanning is dominated by the inner loop that probes one anchor
byte (the first non-wildcard byte of the pattern) at every candidate
offset. This crate ships two implementations of that hot path:

- **SWAR (default)** — portable 8-byte word search using the standard
  "has-zero-byte" bit-twiddle. Pure no_std Rust, no dependencies, works on
  every target rustc supports.
- **memchr (`memchr` feature)** — delegates the anchor scan to the
  [`memchr`](https://crates.io/crates/memchr) crate, which performs runtime
  CPU feature detection and uses AVX2 / SSE2 on x86_64 and NEON on aarch64.

### Benchmark numbers

The bench (`benches/scan.rs`, criterion) searches an 8-byte pattern with one
wildcard (`48 8B 05 ? ? ? ? 48`) inside a 1 MiB buffer of zeros — a worst
case where the anchor byte never matches and the inner loop has to traverse
the entire haystack.

| Backend | `find_in_slice` (1 MiB) | `count_in_slice` (1 MiB) | vs. naive |
| --- | --- | --- | --- |
| Naive byte-by-byte (pre-fastscan) | ~662 µs | ~331 µs | 1× |
| SWAR fallback (default features) | ~102 µs | ~99 µs | **6.5× / 3.3×** |
| memchr (`--features memchr`) | **~10 µs** | **~10 µs** | **63× / 32×** |

Numbers from a Windows 11 / x86_64 box; the relative gap holds on Linux and
macOS. Run `cargo bench` (default backend) or
`cargo bench --features memchr` to reproduce.

### When to enable `memchr`

Enable it when scan throughput matters — typically in-process tooling that
sweeps tens to hundreds of megabytes per pass:

- Internal cheat / mod loaders scanning `client.dll` (~30–60 MB) or
  `GameAssembly.dll` (50–200 MB) at injection time.
- Anti-cheat-aware code that wants to keep the CPU spike short.
- Test harnesses re-running 100+ signatures after every game update.

```toml
[dependencies]
pe-sigscan = { version = "0.1", features = ["memchr"] }
```

For one-shot offline tools (Ghidra/IDA scripts, sig-dev REPLs), the default
SWAR path is already 3–6× faster than naive and you can keep the crate
dependency-free.

## Why direct memory reads?

The `.text` section of a loaded DLL is page-aligned, RX-protected, and stays
committed for the lifetime of the module. There is no TOCTOU concern; bytes
don't change between reads. A typical scan walks tens of megabytes — routing
every probe through `ReadProcessMemory` would cost tens of millions of
syscalls (minutes of wall time). This crate reads directly via raw pointer
dereference, bounded to PE-declared section ranges.

## Safety

The public scanning functions take a `module_base: usize` you obtain from
the OS (e.g. `GetModuleHandleW`). The implementation parses the PE headers
at that base before any other access, so a non-PE pointer is rejected
cleanly. Inside the validated section ranges, the unsafe pointer reads are
bounded by the `VirtualSize` field from the section header — outside the
loader handing us a malformed PE (which the loader itself would have
rejected), there is no path to an out-of-bounds read.

The slice variants (`find_in_slice`, `count_in_slice`) are safe by Rust's
slice invariants and need no further trust from the caller.

## Platform

Windows / PE only.

The crate compiles on every platform — the parsing is pure compute — but
the in-process function signatures assume a `module_base` that came from
the Windows loader. On non-Windows targets, the slice variants
(`find_in_slice`, `count_in_slice`) still work for analyzing PE bytes you
have mapped manually.

## MSRV

Rust 1.70.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
