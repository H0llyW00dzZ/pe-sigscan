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

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use pe_sigscan::{count_in_slice, find_in_slice, pattern};

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
fn bench_find_hit_position(c: &mut Criterion) {
    let pat = pattern!(0x48, 0x8B, 0x05, _, _, _, _, 0x48);
    let pat_bytes = [0x48, 0x8B, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0x48];
    let size = 16 << 20; // 16 MiB
    let mut group = c.benchmark_group("find_hit_position");
    group.throughput(Throughput::Bytes(size as u64));

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
fn bench_pattern_length(c: &mut Criterion) {
    let size = 8 << 20; // 8 MiB
    let haystack = random_haystack(size, 0x1234_5678);
    let mut group = c.benchmark_group("find_pattern_length");
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
            b.iter(|| find_in_slice(black_box(&haystack), black_box(pp)))
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_find_no_hit,
    bench_find_hit_position,
    bench_count,
    bench_pattern_length
);
criterion_main!(benches);
