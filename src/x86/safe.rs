#![allow(clippy::many_single_char_names)]
use crate::consts::BLOCK_LEN;
use core::convert::TryInto;

use crate::consts::PADDING_BLOCK;

#[inline(always)]
fn shl(v: [u32; 4], o: u32) -> [u32; 4] {
    [v[0] >> o, v[1] >> o, v[2] >> o, v[3] >> o]
}

#[inline(always)]
fn shr(v: [u32; 4], o: u32) -> [u32; 4] {
    [v[0] << o, v[1] << o, v[2] << o, v[3] << o]
}

#[inline(always)]
fn or(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    [a[0] | b[0], a[1] | b[1], a[2] | b[2], a[3] | b[3]]
}

#[inline(always)]
fn xor(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
}

#[inline(always)]
fn add(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    [
        a[0].wrapping_add(b[0]),
        a[1].wrapping_add(b[1]),
        a[2].wrapping_add(b[2]),
        a[3].wrapping_add(b[3]),
    ]
}

fn sha256load(v2: [u32; 4], v3: [u32; 4]) -> [u32; 4] {
    [v3[3], v2[0], v2[1], v2[2]]
}

fn sha256swap(v0: [u32; 4]) -> [u32; 4] {
    [v0[2], v0[3], v0[0], v0[1]]
}

fn sha256msg1(v0: [u32; 4], v1: [u32; 4]) -> [u32; 4] {
    // sigma 0 on vectors
    #[inline]
    fn sigma0x4(x: [u32; 4]) -> [u32; 4] {
        let t1 = or(shl(x, 7), shr(x, 25));
        let t2 = or(shl(x, 18), shr(x, 14));
        let t3 = shl(x, 3);
        xor(xor(t1, t2), t3)
    }

    add(v0, sigma0x4(sha256load(v0, v1)))
}

fn sha256msg2(v4: [u32; 4], v3: [u32; 4]) -> [u32; 4] {
    macro_rules! sigma1 {
        ($a:expr) => {
            $a.rotate_right(17) ^ $a.rotate_right(19) ^ ($a >> 10)
        };
    }

    let [x3, x2, x1, x0] = v4;
    let [w15, w14, _, _] = v3;

    let w16 = x0.wrapping_add(sigma1!(w14));
    let w17 = x1.wrapping_add(sigma1!(w15));
    let w18 = x2.wrapping_add(sigma1!(w16));
    let w19 = x3.wrapping_add(sigma1!(w17));

    [w19, w18, w17, w16]
}

fn sha256_digest_round_x2(cdgh: [u32; 4], abef: [u32; 4], wk: [u32; 4]) -> [u32; 4] {
    macro_rules! big_sigma0 {
        ($a:expr) => {
            ($a.rotate_right(2) ^ $a.rotate_right(13) ^ $a.rotate_right(22))
        };
    }
    macro_rules! big_sigma1 {
        ($a:expr) => {
            ($a.rotate_right(6) ^ $a.rotate_right(11) ^ $a.rotate_right(25))
        };
    }
    macro_rules! bool3ary_202 {
        ($a:expr, $b:expr, $c:expr) => {
            $c ^ ($a & ($b ^ $c))
        };
    } // Choose, MD5F, SHA1C
    macro_rules! bool3ary_232 {
        ($a:expr, $b:expr, $c:expr) => {
            ($a & $b) ^ ($a & $c) ^ ($b & $c)
        };
    } // Majority, SHA1M

    let [_, _, wk1, wk0] = wk;
    let [a0, b0, e0, f0] = abef;
    let [c0, d0, g0, h0] = cdgh;

    // a round
    let x0 = big_sigma1!(e0)
        .wrapping_add(bool3ary_202!(e0, f0, g0))
        .wrapping_add(wk0)
        .wrapping_add(h0);
    let y0 = big_sigma0!(a0).wrapping_add(bool3ary_232!(a0, b0, c0));
    let (a1, b1, c1, d1, e1, f1, g1, h1) = (
        x0.wrapping_add(y0),
        a0,
        b0,
        c0,
        x0.wrapping_add(d0),
        e0,
        f0,
        g0,
    );

    // a round
    let x1 = big_sigma1!(e1)
        .wrapping_add(bool3ary_202!(e1, f1, g1))
        .wrapping_add(wk1)
        .wrapping_add(h1);
    let y1 = big_sigma0!(a1).wrapping_add(bool3ary_232!(a1, b1, c1));
    let (a2, b2, _, _, e2, f2, _, _) = (
        x1.wrapping_add(y1),
        a1,
        b1,
        c1,
        x1.wrapping_add(d1),
        e1,
        f1,
        g1,
    );

    [a2, b2, e2, f2]
}

fn schedule(v0: [u32; 4], v1: [u32; 4], v2: [u32; 4], v3: [u32; 4]) -> [u32; 4] {
    let t1 = sha256msg1(v0, v1);
    let t2 = sha256load(v2, v3);
    let t3 = add(t1, t2);
    sha256msg2(t3, v3)
}

#[inline]
fn padding_schedule(w: usize) -> [u32; 4] {
    match w {
        4 => [20616, 2117632, 20971520, 2147483648],
        5 => [2684354592, 84449090, 575995924, 570427392],
        6 => [4202700544, 1496221, 6067200, 1518862336],
        7 => [3003913545, 4142317530, 291985753, 3543279056],
        8 => [2296832490, 216179603, 2642168871, 145928272],
        9 => [1324035729, 3610378607, 1738633033, 2771075893],
        10 => [2822718356, 3803995842, 2397971253, 1572820453],
        11 => [2958106055, 3650881000, 921948365, 1168996599],
        12 => [991993842, 3820646885, 3172022107, 1773959876],
        13 => [85264541, 322392134, 3797604839, 419360279],
        14 => [3328750644, 822159570, 640108622, 1326255876],
        15 => [2242356356, 3852183409, 1657999800, 1107837388],
        _ => panic!("invalid w value {}", w),
    }
}

macro_rules! rounds4 {
    ($abef:ident, $cdgh:ident, $rest:expr, $i:expr) => {{
        let t1 = add($rest, crate::consts::K32X4[$i]);
        $cdgh = sha256_digest_round_x2($cdgh, $abef, t1);
        let t2 = sha256swap(t1);
        $abef = sha256_digest_round_x2($abef, $cdgh, t2);
    }};
}

macro_rules! schedule_rounds4 {
    (
        $abef:ident, $cdgh:ident,
        $w0:expr, $w1:expr, $w2:expr, $w3:expr, $w4:expr,
        $i: expr
    ) => {{
        $w4 = schedule($w0, $w1, $w2, $w3);
        rounds4!($abef, $cdgh, $w4, $i);
    }};
}

macro_rules! padding_schedule_rounds4 {
    (
        $abef:ident, $cdgh:ident,
        $w0:expr, $w1:expr, $w2:expr, $w3:expr, $w4:expr,
        $i: expr
    ) => {{
        $w4 = padding_schedule($i);

        #[cfg(debug_assertions)]
        {
            assert_eq!($w4, schedule($w0, $w1, $w2, $w3), "{}", $i);
        }

        rounds4!($abef, $cdgh, $w4, $i);
    }};
}

macro_rules! digest_block {
    ($state: ident, $block: ident, $schedule: ident) => {
        let mut block = [0u32; BLOCK_LEN];
        for (o, chunk) in block.iter_mut().zip($block.chunks_exact(4)) {
            *o = u32::from_be_bytes(chunk.try_into().unwrap());
        }

        let mut abef = [$state[0], $state[1], $state[4], $state[5]];
        let mut cdgh = [$state[2], $state[3], $state[6], $state[7]];

        // Rounds 0..64
        let mut w0 = [block[3], block[2], block[1], block[0]];
        let mut w1 = [block[7], block[6], block[5], block[4]];
        let mut w2 = [block[11], block[10], block[9], block[8]];
        let mut w3 = [block[15], block[14], block[13], block[12]];
        let mut w4;

        rounds4!(abef, cdgh, w0, 0);
        rounds4!(abef, cdgh, w1, 1);
        rounds4!(abef, cdgh, w2, 2);
        rounds4!(abef, cdgh, w3, 3);
        $schedule!(abef, cdgh, w0, w1, w2, w3, w4, 4);
        $schedule!(abef, cdgh, w1, w2, w3, w4, w0, 5);
        $schedule!(abef, cdgh, w2, w3, w4, w0, w1, 6);
        $schedule!(abef, cdgh, w3, w4, w0, w1, w2, 7);
        $schedule!(abef, cdgh, w4, w0, w1, w2, w3, 8);
        $schedule!(abef, cdgh, w0, w1, w2, w3, w4, 9);
        $schedule!(abef, cdgh, w1, w2, w3, w4, w0, 10);
        $schedule!(abef, cdgh, w2, w3, w4, w0, w1, 11);
        $schedule!(abef, cdgh, w3, w4, w0, w1, w2, 12);
        $schedule!(abef, cdgh, w4, w0, w1, w2, w3, 13);
        $schedule!(abef, cdgh, w0, w1, w2, w3, w4, 14);
        $schedule!(abef, cdgh, w1, w2, w3, w4, w0, 15);

        let [a, b, e, f] = abef;
        let [c, d, g, h] = cdgh;

        $state[0] = $state[0].wrapping_add(a);
        $state[1] = $state[1].wrapping_add(b);
        $state[2] = $state[2].wrapping_add(c);
        $state[3] = $state[3].wrapping_add(d);
        $state[4] = $state[4].wrapping_add(e);
        $state[5] = $state[5].wrapping_add(f);
        $state[6] = $state[6].wrapping_add(g);
        $state[7] = $state[7].wrapping_add(h);
    };
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut state = crate::consts::H256_256;

    digest_block!(state, bytes, schedule_rounds4);
    digest_block!(state, PADDING_BLOCK, padding_schedule_rounds4);

    let mut output = [0; 32];
    output[0..4].copy_from_slice(&state[0].to_be_bytes());
    output[4..8].copy_from_slice(&state[1].to_be_bytes());
    output[8..12].copy_from_slice(&state[2].to_be_bytes());
    output[12..16].copy_from_slice(&state[3].to_be_bytes());
    output[16..20].copy_from_slice(&state[4].to_be_bytes());
    output[20..24].copy_from_slice(&state[5].to_be_bytes());
    output[24..28].copy_from_slice(&state[6].to_be_bytes());
    output[28..32].copy_from_slice(&state[7].to_be_bytes());
    output
}
