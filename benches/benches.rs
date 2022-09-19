#![feature(test)]

extern crate test;
use digest::Digest;
use sha2::Sha256;
use test::Bencher;

const PREIMAGE: [u8; 64] = [42; 64];
const RUNS: usize = 100_000;

#[bench]
fn optimised(b: &mut Bencher) {
    b.iter(|| {
        // Use `test::black_box` to prevent compiler optimizations from disregarding
        // Unused values
        test::black_box(for _ in 0..RUNS {
            sha2_fixed_64::x86::sha256(&PREIMAGE);
        });
    });
}

#[bench]
fn unoptimised(b: &mut Bencher) {
    b.iter(|| {
        // Use `test::black_box` to prevent compiler optimizations from disregarding
        // Unused values
        test::black_box(for _ in 0..RUNS {
            let mut digest = Sha256::new();
            digest.update(&PREIMAGE);
            let _: [u8; 32] = digest.finalize().into();
        });
    });
}
