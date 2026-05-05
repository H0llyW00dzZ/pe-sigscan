//! Comprehensive benchmark suite for pe-sigscan.
//!
//! Exercises the scan hot path across the dimensions that matter for real
//! workloads:
//!
//! - **Haystack size**: 1 MiB → 64 MiB, mirroring DLL `.text` sizes from
//!   small game DLLs up to IL2CPP `GameAssembly.dll` and AAA monoliths.
//! - **Haystack content**: all-zeros (worst case for the anchor pre-filter,
//!   never matches) and pseudo-random bytes (realistic game-binary-like
//!   distribution where the anchor byte appears every ~256 offsets).
//! - **Pattern length**: 4 / 8 / 20 / 40 bytes — covers tiny prologues,
//!   typical IDA signatures, and verbose long sigs.
//! - **Wildcard density**: dense bytes (one wildcard) vs sparse (all
//!   wildcards but the anchor) — the latter stresses `matches_at` more.
//! - **Hit position**: no hit, hit at end, hit at start — measures both
//!   best-case early-exit and worst-case full-sweep throughput.
//! - **API**: `find_in_slice` (early exit) vs `count_in_slice` (always
//!   scans the entire haystack).
//!
//! Throughput is reported in bytes/sec so results are directly comparable
//! across haystack sizes — a 1 MiB scan and a 64 MiB scan should show the
//! same GB/s when the inner loop is the bottleneck.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use pe_sigscan::{
    count_in_slice, find_in_slice, iter_in_slice, pattern, read_rel32, resolve_rel32,
    resolve_rel32_at, Pattern,
};
use std::hint::black_box;

// ----------------------------------------------------------------------
// Haystack generators
// ----------------------------------------------------------------------

/// All-zero haystack. Worst case for the anchor pre-filter: the anchor
/// byte (0x48) never appears, so every implementation has to traverse the
/// entire buffer once.
fn zero_haystack(size: usize) -> Vec<u8> {
    vec![0u8; size]
}

/// Pseudo-random haystack via xorshift64. Reproducible (no rng dep) and
/// gives a uniform byte distribution, so the anchor byte 0x48 occurs on
/// average every 256 offsets — close to a realistic compiled `.text`.
fn random_haystack(size: usize, seed: u64) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    let mut s = seed.max(1);
    for chunk in buf.chunks_mut(8) {
        // xorshift64
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        let bytes = s.to_le_bytes();
        for (dst, src) in chunk.iter_mut().zip(bytes.iter()) {
            *dst = *src;
        }
    }
    buf
}

/// Plant `pat_bytes` at byte offset `at` inside `haystack`. Used to
/// measure best/worst-case `find_in_slice` early-exit behaviour.
fn plant(haystack: &mut [u8], at: usize, pat_bytes: &[u8]) {
    haystack[at..at + pat_bytes.len()].copy_from_slice(pat_bytes);
}

// ----------------------------------------------------------------------
// Benchmarks
// ----------------------------------------------------------------------

/// `find_in_slice` across multiple haystack sizes and content types,
/// measured as throughput so all sizes can be compared on the same axis.
fn bench_find_no_hit(c: &mut Criterion) {
    // 8-byte pattern with one wildcard — typical cheat sig.
    let pat = pattern!(0x48, 0x8B, 0x05, _, _, _, _, 0x48);
    let mut group = c.benchmark_group("find_no_hit");

    for &size in &[1 << 20, 8 << 20, 64 << 20] {
        group.throughput(Throughput::Bytes(size as u64));

        let zero = zero_haystack(size);
        group.bench_with_input(BenchmarkId::new("zero", size), &zero, |b, h| {
            b.iter(|| find_in_slice(black_box(h), black_box(pat)))
        });

        let rand = random_haystack(size, 0xDEAD_BEEF);
        group.bench_with_input(BenchmarkId::new("random", size), &rand, |b, h| {
            b.iter(|| find_in_slice(black_box(h), black_box(pat)))
        });
    }

    group.finish();
}

/// Same as `find_no_hit` but the pattern is planted near the start, end,
/// and middle of the haystack to measure early-exit behaviour.
///
/// **Latency, not throughput.** This bench deliberately does NOT call
/// `group.throughput(...)` because `find_in_slice` short-circuits on the
/// first match — when the match is near the start, only ~1 % of the
/// buffer is actually read before the scanner returns. Reporting
/// `bytes_total / elapsed` would yield bogus "925 GiB/s" numbers that
/// exceed DRAM bandwidth by 10×+ and mislead the reader. The
/// meaningful metric here is the **wall-clock time** difference
/// between `start` / `middle` / `end` — a near-linear progression
/// confirms that early-exit is working, while a flat result would mean
/// the scanner is incorrectly traversing the full buffer regardless of
/// match position.
fn bench_find_hit_position(c: &mut Criterion) {
    let pat = pattern!(0x48, 0x8B, 0x05, _, _, _, _, 0x48);
    let pat_bytes = [0x48, 0x8B, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0x48];
    let size = 16 << 20; // 16 MiB
    let mut group = c.benchmark_group("find_hit_position");
    // No `group.throughput(...)` — see doc comment above.

    for &(label, frac) in &[("start", 0.01_f64), ("middle", 0.5_f64), ("end", 0.99_f64)] {
        let mut buf = zero_haystack(size);
        let pos = (size as f64 * frac) as usize;
        plant(&mut buf, pos.min(size - pat_bytes.len()), &pat_bytes);
        group.bench_with_input(BenchmarkId::from_parameter(label), &buf, |b, h| {
            b.iter(|| find_in_slice(black_box(h), black_box(pat)))
        });
    }

    group.finish();
}

/// `count_in_slice` does not early-exit — it always traverses the full
/// haystack. Useful to measure raw inner-loop throughput.
fn bench_count(c: &mut Criterion) {
    let pat = pattern!(0x48, 0x8B, 0x05, _, _, _, _, 0x48);
    let mut group = c.benchmark_group("count");

    for &size in &[1 << 20, 8 << 20, 64 << 20] {
        group.throughput(Throughput::Bytes(size as u64));

        let zero = zero_haystack(size);
        group.bench_with_input(BenchmarkId::new("zero", size), &zero, |b, h| {
            b.iter(|| count_in_slice(black_box(h), black_box(pat)))
        });

        let rand = random_haystack(size, 0xCAFE_BABE);
        group.bench_with_input(BenchmarkId::new("random", size), &rand, |b, h| {
            b.iter(|| count_in_slice(black_box(h), black_box(pat)))
        });
    }

    group.finish();
}

/// Pattern length sweep. The anchor pre-filter cost is constant per
/// candidate; longer patterns make `matches_at` cost more on the hits
/// the anchor lets through, so this is most visible on `random` content
/// where the anchor byte hits often.
///
/// Uses `count_in_slice` rather than `find_in_slice` because `count`
/// always traverses the full haystack regardless of pattern content,
/// while `find` early-exits on the first match. With a `random`
/// haystack and a short pattern (e.g. `len_4` with 2 fixed bytes), a
/// chance match lands at ~64 KiB into the buffer and `find` returns
/// after reading 1 % of the bytes — making `Throughput::Bytes(size)`
/// report bogus 3000+ GiB/s numbers (faster than DRAM bandwidth) that
/// aren't comparable across pattern lengths. `count` keeps the work
/// constant per pattern-length variant so the throughput axis stays
/// honest and the only thing varying is the per-anchor-hit
/// `matches_at` cost we actually want to measure.
fn bench_pattern_length(c: &mut Criterion) {
    let size = 8 << 20; // 8 MiB
    let haystack = random_haystack(size, 0x1234_5678);
    let mut group = c.benchmark_group("count_pattern_length");
    group.throughput(Throughput::Bytes(size as u64));

    let p4: &[Option<u8>] = pattern!(0x48, 0x8B, _, _);
    let p8: &[Option<u8>] = pattern!(0x48, 0x8B, 0x05, _, _, _, _, 0x48);
    let p20: &[Option<u8>] = pattern!(
        0x48, 0x89, 0x5C, 0x24, _, 0x48, 0x89, 0x74, 0x24, _, 0x48, 0x89, 0x7C, 0x24, _, 0x55,
        0x41, 0x56, 0x41, 0x57
    );
    let p40: &[Option<u8>] = pattern!(
        0x48, 0x89, 0x5C, 0x24, _, 0x48, 0x89, 0x74, 0x24, _, 0x48, 0x89, 0x7C, 0x24, _, 0x55,
        0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x40, 0x48, 0x8B, 0xF1, 0x48, 0x8B, 0xFA, 0x49,
        0x8B, 0xD8, _, _, _, _, 0x48, 0x8B, 0xCB
    );

    for (label, p) in [
        ("len_4", p4),
        ("len_8", p8),
        ("len_20", p20),
        ("len_40", p40),
    ] {
        group.bench_with_input(BenchmarkId::from_parameter(label), &p, |b, &pp| {
            b.iter(|| count_in_slice(black_box(&haystack), black_box(pp)))
        });
    }

    group.finish();
}

// ----------------------------------------------------------------------
// Iterator benchmarks (iter_in_slice)
// ----------------------------------------------------------------------

/// Compare iterator-driven match enumeration against the dedicated
/// single-shot scanners. The iterator is built on the same
/// `scan_slice_from` / `scan_range_from` primitives, so:
///
/// - `iter_in_slice(..).count()` should track `count_in_slice(..)` to
///   within noise on the same content.
/// - `iter_in_slice(..).next()` should track `find_in_slice(..)`.
///
/// A measurable gap on either pair points at unintended overhead in the
/// iterator state machine (cursor / `pat_len == 0` short-circuits, etc.)
/// and is the signal to dig in.
fn bench_iter_in_slice(c: &mut Criterion) {
    // 8 MiB random haystack — anchor byte (0x48) hits ~32k times, of
    // which only a handful pass the full pattern check. Realistic for a
    // signature with one wildcard.
    let size = 8 << 20;
    let buf = random_haystack(size, 0xBABE_FACE);
    let pat = pattern!(0x48, 0x8B, 0x05, _, _, _, _, 0x48);

    let mut group = c.benchmark_group("iter_in_slice");
    group.throughput(Throughput::Bytes(size as u64));

    // -- "walk every match" forms ----------------------------------------
    group.bench_function("iter_count", |b| {
        b.iter(|| iter_in_slice(black_box(&buf), black_box(pat)).count())
    });
    group.bench_function("count_in_slice (reference)", |b| {
        b.iter(|| count_in_slice(black_box(&buf), black_box(pat)))
    });

    // -- "first match only" forms ----------------------------------------
    group.bench_function("iter_next", |b| {
        b.iter(|| iter_in_slice(black_box(&buf), black_box(pat)).next())
    });
    group.bench_function("find_in_slice (reference)", |b| {
        b.iter(|| find_in_slice(black_box(&buf), black_box(pat)))
    });

    group.finish();
}

/// Iterator throughput as a function of match density. As more matches
/// land in the haystack the per-match overhead (cursor advance, return
/// from `next()`, caller-side accumulation) starts to bite. This bench
/// quantifies that.
///
/// At sparse densities the bench should be I/O-bound (anchor pre-filter
/// dominates); at dense densities it transitions to overhead-bound.
fn bench_iter_match_density(c: &mut Criterion) {
    let size = 8 << 20;
    let pat_bytes = [0x48, 0x8B, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0x48];
    let pat = pattern!(0x48, 0x8B, 0x05, _, _, _, _, 0x48);

    let mut group = c.benchmark_group("iter_match_density");
    group.throughput(Throughput::Bytes(size as u64));

    for &n_matches in &[1usize, 16, 256, 4096] {
        let mut buf = zero_haystack(size);
        // Spread matches uniformly across the haystack.
        let stride = size / (n_matches + 1);
        for i in 0..n_matches {
            let off = (stride * (i + 1)).min(size - pat_bytes.len());
            plant(&mut buf, off, &pat_bytes);
        }
        group.bench_with_input(BenchmarkId::from_parameter(n_matches), &buf, |b, h| {
            b.iter(|| {
                let mut acc = 0usize;
                for addr in iter_in_slice(black_box(h), black_box(pat)) {
                    acc = acc.wrapping_add(addr);
                }
                black_box(acc)
            })
        });
    }

    group.finish();
}

// ----------------------------------------------------------------------
// rel32 helper benchmarks
// ----------------------------------------------------------------------

/// Build a buffer of `n` synthetic `call rel32` instructions
/// (`E8 ?? ?? ?? ??`) packed back-to-back. Used to drive the rel32
/// helpers in a tight loop without the noise of an outer scan.
fn synthetic_call_buffer(n: usize) -> Vec<u8> {
    const INSTR_LEN: usize = 5;
    let mut buf = vec![0u8; n * INSTR_LEN];
    for i in 0..n {
        let off = i * INSTR_LEN;
        buf[off] = 0xE8;
        // Vary the displacement so the compiler can't constant-fold the
        // resolved targets across iterations.
        let disp = (i as i32).wrapping_mul(0x0101_0101);
        buf[off + 1..off + INSTR_LEN].copy_from_slice(&disp.to_le_bytes());
    }
    buf
}

/// Throughput of the rel32 helpers in isolation. These are a few
/// instructions each (load + sign-extend + add); the loop itself
/// dominates, so the absolute number measures `resolve_rel32` + ~3 ALU
/// ops of bookkeeping per iteration. Useful to watch for regressions
/// (e.g. accidentally introducing a branch or losing the inline).
fn bench_rel32_helpers(c: &mut Criterion) {
    const N: usize = 1 << 16; // 65,536 instructions
    const INSTR_LEN: usize = 5;
    let buf = synthetic_call_buffer(N);
    let base = buf.as_ptr() as usize;

    let mut group = c.benchmark_group("rel32_helpers");
    group.throughput(Throughput::Elements(N as u64));

    // resolve_rel32: raw 2-arg form.
    group.bench_function("resolve_rel32", |b| {
        b.iter(|| {
            let mut acc: usize = 0;
            for i in 0..N {
                let addr = base + i * INSTR_LEN;
                acc = acc.wrapping_add(unsafe {
                    resolve_rel32(black_box(addr + 1), black_box(addr + INSTR_LEN))
                });
            }
            black_box(acc)
        })
    });

    // resolve_rel32_at: convenience wrapper. Should compile down to the
    // exact same code as `resolve_rel32` after inlining.
    group.bench_function("resolve_rel32_at", |b| {
        b.iter(|| {
            let mut acc: usize = 0;
            for i in 0..N {
                let addr = base + i * INSTR_LEN;
                acc = acc.wrapping_add(unsafe { resolve_rel32_at(black_box(addr), 1, INSTR_LEN) });
            }
            black_box(acc)
        })
    });

    // read_rel32: safe slice variant. Slightly more expensive due to
    // bounds-checking, but still single-load on the happy path.
    group.bench_function("read_rel32", |b| {
        b.iter(|| {
            let mut acc: i64 = 0;
            for i in 0..N {
                let off = i * INSTR_LEN;
                acc = acc.wrapping_add(read_rel32(black_box(&buf), off + 1).unwrap_or(0) as i64);
            }
            black_box(acc)
        })
    });

    group.finish();
}

// ----------------------------------------------------------------------
// End-to-end "scan + resolve" workflow
// ----------------------------------------------------------------------

/// The realistic cheat / mod-loader pipeline: scan a `.text`-sized
/// haystack for an instruction signature, then for each match resolve
/// the rel32 displacement to its absolute target.
///
/// Benchmarked alongside a "scan-only" baseline so the per-match
/// resolution overhead is visible against the scan cost. In practice the
/// scan dominates by 3+ orders of magnitude on real binaries — this
/// bench confirms that.
fn bench_scan_and_resolve(c: &mut Criterion) {
    // 8 MiB random haystack with 64 planted call instructions, evenly
    // spread. Anchor byte (0xE8) appears more often than in a real
    // binary because the random distribution puts it ~1/256 offsets, so
    // this is a slight pessimisation of the iterator path — fine; it
    // gives a clean upper bound on overhead.
    let size = 8 << 20;
    let mut buf = random_haystack(size, 0x9999_AAAA);
    let pat_bytes = [0xE8, 0x78, 0x56, 0x34, 0x12];
    let n_planted = 64;
    let stride = size / (n_planted + 1);
    for i in 0..n_planted {
        let off = (stride * (i + 1)).min(size - pat_bytes.len());
        plant(&mut buf, off, &pat_bytes);
    }
    let pat = pattern!(0xE8, _, _, _, _);

    let mut group = c.benchmark_group("scan_and_resolve");
    group.throughput(Throughput::Bytes(size as u64));

    // Scan only — establishes the baseline cost of walking the haystack.
    group.bench_function("iter_only", |b| {
        b.iter(|| {
            let mut acc: usize = 0;
            for addr in iter_in_slice(black_box(&buf), black_box(pat)) {
                acc = acc.wrapping_add(addr);
            }
            black_box(acc)
        })
    });

    // Scan + resolve every match — the realistic workflow used by
    // hookers / cheats / anti-cheat-aware analysers.
    group.bench_function("iter_then_resolve_rel32_at", |b| {
        b.iter(|| {
            let mut acc: usize = 0;
            for addr in iter_in_slice(black_box(&buf), black_box(pat)) {
                acc = acc.wrapping_add(unsafe { resolve_rel32_at(addr, 1, 5) });
            }
            black_box(acc)
        })
    });

    // Same workflow but using the safe `read_rel32` slice helper to do
    // the displacement read. Includes the bounds check on every match.
    // The base address used for the absolute-address arithmetic is the
    // slice's start — equivalent to what the in-process variant does
    // with `module_base` at runtime.
    group.bench_function("iter_then_read_rel32", |b| {
        let base = buf.as_ptr() as usize;
        b.iter(|| {
            let mut acc: usize = 0;
            for addr in iter_in_slice(black_box(&buf), black_box(pat)) {
                let off = addr - base;
                let disp = read_rel32(black_box(&buf), off + 1).unwrap_or(0) as isize;
                acc = acc.wrapping_add(((addr + 5) as isize).wrapping_add(disp) as usize);
            }
            black_box(acc)
        })
    });

    group.finish();
}

// ----------------------------------------------------------------------
// Pattern parsing
// ----------------------------------------------------------------------

fn bench_pattern_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("pattern_parse");

    let short = "48 8B 05 ?? ?? ?? ??";
    let medium = "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F9 48 8B";
    let long = (0..40)
        .map(|i| if i % 3 == 0 { "??" } else { "48" })
        .collect::<Vec<_>>()
        .join(" ");

    for (name, pat) in [("short", short), ("medium", medium), ("long", &long)] {
        group.bench_function(name, |b| {
            b.iter(|| Pattern::from_ida(black_box(pat)).unwrap())
        });
    }

    group.finish();
}

// ----------------------------------------------------------------------
// First-byte search (fastscan hot path)
// ----------------------------------------------------------------------

fn bench_first_byte_search(c: &mut Criterion) {
    let mut group = c.benchmark_group("first_byte_search");
    let haystack: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
    let needle = 0xDE;

    group.throughput(Throughput::Bytes(haystack.len() as u64));
    group.bench_function("first_byte_in_slice", |b| {
        b.iter(|| pe_sigscan::find_in_slice(black_box(&haystack), black_box(&[Some(needle)])))
    });

    group.finish();
}

// ----------------------------------------------------------------------
// Multi-section executable scanning (pe + scan)
// ----------------------------------------------------------------------

fn bench_exec_sections(c: &mut Criterion) {
    let mut group = c.benchmark_group("exec_sections");
    let haystack: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
    let pat = pattern![0xDE, _, _, _, 0xBE];

    group.throughput(Throughput::Bytes(haystack.len() as u64));
    group.bench_function("find_in_exec_sections", |b| {
        b.iter(|| find_in_slice(black_box(&haystack), black_box(pat)))
    });
    group.bench_function("count_in_exec_sections", |b| {
        b.iter(|| count_in_slice(black_box(&haystack), black_box(pat)))
    });

    group.finish();
}

// ----------------------------------------------------------------------
// Synthetic PE multi-section scenarios
// ----------------------------------------------------------------------

fn bench_synthetic_pe(c: &mut Criterion) {
    let mut group = c.benchmark_group("synthetic_pe");
    // Simulate a PE with .text + .text$mn + .textbss style layout
    let mut buf = vec![0u8; 512 * 1024];
    // Plant matches in different "sections"
    buf[100] = 0x48;
    buf[101] = 0x8B;
    buf[200_000] = 0x48;
    buf[200_001] = 0x8B;
    buf[400_000] = 0x48;
    buf[400_001] = 0x8B;

    let pat = pattern![0x48, 0x8B, _, _];

    group.throughput(Throughput::Bytes(buf.len() as u64));
    group.bench_function("find_across_sections", |b| {
        b.iter(|| find_in_slice(black_box(&buf), black_box(pat)))
    });
    group.bench_function("count_across_sections", |b| {
        b.iter(|| count_in_slice(black_box(&buf), black_box(pat)))
    });
    group.bench_function("iter_across_sections", |b| {
        b.iter(|| iter_in_slice(black_box(&buf), black_box(pat)).count())
    });

    group.finish();
}

// ----------------------------------------------------------------------
// Fastscan primitives (SWAR / first-byte search edge cases)
// ----------------------------------------------------------------------

fn bench_fastscan_primitives(c: &mut Criterion) {
    let mut group = c.benchmark_group("fastscan");

    // Empty slice
    let empty: &[u8] = &[];
    group.bench_function("empty_slice", |b| {
        b.iter(|| find_in_slice(black_box(empty), black_box(&[Some(0x48)])))
    });

    // Finds in tail (pattern near end of buffer)
    let mut tail = vec![0u8; 4096];
    tail[4090] = 0x48;
    tail[4091] = 0x8B;
    let pat_tail = pattern![0x48, 0x8B];
    group.bench_function("finds_in_tail", |b| {
        b.iter(|| find_in_slice(black_box(&tail), black_box(pat_tail)))
    });

    // SWAR high-bit bytes (stress the bit-twiddling path)
    let high_bit: Vec<u8> = (0..8192).map(|i| if i % 7 == 0 { 0x80 | (i as u8) } else { i as u8 }).collect();
    let pat_high = pattern![0xDE];
    group.bench_function("swar_high_bit_bytes", |b| {
        b.iter(|| find_in_slice(black_box(&high_bit), black_box(pat_high)))
    });

    // First-byte absent (worst case for anchor scan)
    let absent: Vec<u8> = (0..1024 * 1024).map(|i| (i % 250) as u8).collect();
    let pat_absent = pattern![0xFF, _, _, _];
    group.throughput(Throughput::Bytes(absent.len() as u64));
    group.bench_function("returns_none_when_absent", |b| {
        b.iter(|| find_in_slice(black_box(&absent), black_box(pat_absent)))
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets =
        bench_find_no_hit,
        bench_find_hit_position,
        bench_count,
        bench_pattern_length,
        bench_iter_in_slice,
        bench_iter_match_density,
        bench_rel32_helpers,
        bench_scan_and_resolve,
        bench_pattern_parse,
        bench_first_byte_search,
        bench_exec_sections,
        bench_synthetic_pe,
        bench_fastscan_primitives,
}
criterion_main!(benches);
