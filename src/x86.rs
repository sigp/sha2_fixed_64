#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

const PADDING_BLOCK: [u8; 64] = [
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
];

#[inline]
unsafe fn schedule(v0: __m128i, v1: __m128i, v2: __m128i, v3: __m128i) -> __m128i {
    let t1 = _mm_sha256msg1_epu32(v0, v1);
    let t2 = _mm_alignr_epi8(v3, v2, 4);
    let t3 = _mm_add_epi32(t1, t2);
    _mm_sha256msg2_epu32(t3, v3)
}

#[inline]
unsafe fn padding_schedule(w: usize) -> __m128i {
    match w {
        4 => _mm_set_epi64x(88545047891968, 90071994694893568),
        5 => _mm_set_epi64x(-6917528890117679294, 2473883656779728896),
        6 => _mm_set_epi64x(-396282682346646371, 26058427097153536),
        7 => _mm_set_epi64x(-5545033633780809766, 1254069263576212944),
        8 => _mm_set_epi64x(-8581923644553124973, -7098715182109380528),
        9 => _mm_set_epi64x(5686690158400897391, 7467372019251364661),
        10 => _mm_set_epi64x(-6323261045066670398, -8147535963753589275),
        11 => _mm_set_epi64x(-5741775305734093336, 3959738077444667639),
        12 => _mm_set_epi64x(4260581113044038117, -4823012860181579068),
        13 => _mm_set_epi64x(366208415425843270, -2136155486653845993),
        14 => _mm_set_epi64x(-4149868920368453422, 2749245598703881988),
        15 => _mm_set_epi64x(-8815896854859634831, 7121054918882378188),
        _ => panic!("invalid w value {}", w),
    }
}

macro_rules! rounds4 {
    ($abef:ident, $cdgh:ident, $rest:expr, $i:expr) => {{
        let k = crate::consts::K32X4[$i];
        let kv = _mm_set_epi32(k[0] as i32, k[1] as i32, k[2] as i32, k[3] as i32);
        let t1 = _mm_add_epi32($rest, kv);
        $cdgh = _mm_sha256rnds2_epu32($cdgh, $abef, t1);
        let t2 = _mm_shuffle_epi32(t1, 0x0E);
        $abef = _mm_sha256rnds2_epu32($abef, $cdgh, t2);
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
            assert_eq!(
                as_i64x4($w4),
                as_i64x4(schedule($w0, $w1, $w2, $w3)),
                "{}",
                $i
            );
        }

        rounds4!($abef, $cdgh, $w4, $i);
    }};
}

#[cfg(debug_assertions)]
unsafe fn as_i64x4(i: __m128i) -> [i64; 2] {
    [_mm_extract_epi64(i, 0), _mm_extract_epi64(i, 1)]
}

// we use unaligned loads with `__m128i` pointers
#[allow(clippy::cast_ptr_alignment)]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
#[inline]
unsafe fn digest_blocks(state: &mut [u32; 8], message: &[u8; 64]) {
    #[allow(non_snake_case)]
    let MASK: __m128i = _mm_set_epi64x(
        0x0C0D_0E0F_0809_0A0Bu64 as i64,
        0x0405_0607_0001_0203u64 as i64,
    );

    let state_ptr = state.as_ptr() as *const __m128i;
    let dcba = _mm_loadu_si128(state_ptr.add(0));
    let efgh = _mm_loadu_si128(state_ptr.add(1));

    let cdab = _mm_shuffle_epi32(dcba, 0xB1);
    let efgh = _mm_shuffle_epi32(efgh, 0x1B);
    let mut abef = _mm_alignr_epi8(cdab, efgh, 8);
    let mut cdgh = _mm_blend_epi16(efgh, cdab, 0xF0);

    macro_rules! process_block {
        ($block: ident, $schedule: ident) => {
            let abef_save = abef;
            let cdgh_save = cdgh;

            let data_ptr = $block.as_ptr() as *const __m128i;
            let mut w0 = _mm_shuffle_epi8(_mm_loadu_si128(data_ptr.add(0)), MASK);
            let mut w1 = _mm_shuffle_epi8(_mm_loadu_si128(data_ptr.add(1)), MASK);
            let mut w2 = _mm_shuffle_epi8(_mm_loadu_si128(data_ptr.add(2)), MASK);
            let mut w3 = _mm_shuffle_epi8(_mm_loadu_si128(data_ptr.add(3)), MASK);
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

            abef = _mm_add_epi32(abef, abef_save);
            cdgh = _mm_add_epi32(cdgh, cdgh_save);
        };
    }

    process_block!(message, schedule_rounds4);
    process_block!(PADDING_BLOCK, padding_schedule_rounds4);

    let feba = _mm_shuffle_epi32(abef, 0x1B);
    let dchg = _mm_shuffle_epi32(cdgh, 0xB1);
    let dcba = _mm_blend_epi16(feba, dchg, 0xF0);
    let hgef = _mm_alignr_epi8(dchg, feba, 8);

    let state_ptr_mut = state.as_mut_ptr() as *mut __m128i;
    _mm_storeu_si128(state_ptr_mut.add(0), dcba);
    _mm_storeu_si128(state_ptr_mut.add(1), hgef);
}

cpufeatures::new!(shani_cpuid, "sha", "sse2", "ssse3", "sse4.1");

pub fn cpu_is_supported() -> bool {
    shani_cpuid::get()
}

pub fn sha256(message: &[u8; 64]) -> [u8; 32] {
    let mut state = crate::consts::H256_256;

    unsafe {
        digest_blocks(&mut state, message);
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use digest::Digest;
    use sha2::Sha256;

    const MESSAGE_ALL_42: [u8; 64] = [42; 64];
    const MESSAGE_ALL_256: [u8; 64] = [255; 64];

    #[test]
    fn message_all_256() {
        let mut digest = Sha256::new();
        digest.update(MESSAGE_ALL_256);
        let reference: [u8; 32] = digest.finalize().into();

        let tested = sha256(&MESSAGE_ALL_256);
        assert_eq!(reference, tested);
    }

    #[test]
    fn message_all_42() {
        let mut digest = Sha256::new();
        digest.update(MESSAGE_ALL_42);
        let reference: [u8; 32] = digest.finalize().into();

        let tested = sha256(&MESSAGE_ALL_42);
        assert_eq!(reference, tested);
    }
}
