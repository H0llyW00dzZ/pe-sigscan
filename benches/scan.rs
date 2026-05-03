use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pe_sigscan::{count_in_slice, find_in_slice, pattern};

fn bench_scan(c: &mut Criterion) {
    // Realistic 8-byte pattern with one wildcard (common in game cheats)
    let pat = pattern!(0x48, 0x8B, 0x05, _, _, _, _, 0x48);
    let haystack = vec![0u8; 1024 * 1024]; // 1 MiB synthetic buffer

    c.bench_function("find_in_slice", |b| {
        b.iter(|| find_in_slice(black_box(&haystack), black_box(pat)))
    });

    c.bench_function("count_in_slice", |b| {
        b.iter(|| count_in_slice(black_box(&haystack), black_box(pat)))
    });
}

criterion_group!(benches, bench_scan);
criterion_main!(benches);
