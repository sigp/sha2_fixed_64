#![feature(test)]

extern crate test;
use digest::Digest;
use sha2::Sha256;
use sha2_fixed_64::x86::{safe, sha_ni};
use test::Bencher;

const PREIMAGE: [u8; 64] = [42; 64];
const RUNS: usize = 1_000;

#[bench]
fn sha_ni(b: &mut Bencher) {
    b.iter(|| {
        // The benches will always fail with a SIGILL if the CPU doesn't support sha instructions.
        if !sha_ni::cpu_is_supported() {
            return;
        }

        // Use `test::black_box` to prevent compiler optimizations from disregarding
        // Unused values
        test::black_box(for _ in 0..RUNS {
            sha_ni::sha256(&PREIMAGE);
        });
    });
}

#[bench]
fn safe(b: &mut Bencher) {
    b.iter(|| {
        // Use `test::black_box` to prevent compiler optimizations from disregarding
        // Unused values
        test::black_box(for _ in 0..RUNS {
            safe::sha256(&PREIMAGE);
        });
    });
}

#[bench]
fn sha2_crate(b: &mut Bencher) {
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

#[bench]
fn ring_crate(b: &mut Bencher) {
    b.iter(|| {
        // Use `test::black_box` to prevent compiler optimizations from disregarding
        // Unused values
        test::black_box(for _ in 0..RUNS {
            let mut context = ring::digest::Context::new(&ring::digest::SHA256);
            context.update(&PREIMAGE);
            let mut output = [0; 32];
            output.copy_from_slice(context.finish().as_ref());
        });
    });
}
