// adapted from https://gitlab.com/tspiteri/fixed
// Copyright © 2018–2020 Trevor Spiteri (licensed under the Apache License, Version 2.0)
// Modifications Copyright (c) 2018-2020 Crypto.com (licensed under the Apache License, Version 2.0)

//! ## `mul`
///
/// ```plain
/// Fixed(a) * Fixed(b)
/// = (a * SCALE) * (b * SCALE)
/// = (a * b) * (SCALE * SCALE)
/// = (a * b * SCALE) * SCALE
/// = Fixed(a * b * SCALE)
/// = Fixed((a * b) >> 63)
/// ```
///
/// But simply multiply two `u128` and shift will cause unnesseary overflow of intermidiate result, we need some tricks to prevent that:
///
/// ```plain
/// a = hi_a * 2 ^ 64 + lo_a
/// b = hi_b * 2 ^ 64 + lo_b
///
/// a * b
/// = (hi_a * 2 ^ 64 + lo_a) * (hi_b * 2 ^ 64 + lo_b)
/// = hi_a * hi_b * 2 ^ 128
///   + (hi_a * lo_b + lo_a * hi_b) * 2 ^ 64
///   + lo_a * lo_b
/// // aliases
/// = hh * 2 ^ 128
///   + (hl + lh) * 2 ^ 64
///   + ll
/// = hh * 2 ^ 128
///   + (hl + lh) * 2 ^ 64
///   + (ll_hi * 2 ^ 64 + ll_lo)
/// = hh * 2 ^ 128
///   + (hl + lh + ll_hi) * 2 ^ 64
///   + ll_lo
/// = hh * 2 ^ 128
///   // lh' = lh + ll_hi
///   // it's safe because: (u64::MAX * u64::MAX) + u64::MAX < u128::MAX
///   + (hl + lh') * 2 ^ 64
///   + ll_lo
/// = hh * 2 ^ 128
///   // overflowing_add, carry_c is either 0 or 1
///   + (carry_c * 2 ^ 128 + c_hi * 2 ^ 64 + c_lo) * 2 ^ 64
///   + ll_lo
/// = (hh + carry_c * 2 ^ 64 + c_hi) * 2 ^ 128
///   + c_lo * 2 ^ 64 + ll_lo
/// = d_hi * 2 ^ 128 + d_lo
///
/// result = combine_hi_lo_shift(d_hi, d_lo, 63);
/// ```
use core::ops;

use super::{hi_lo, hi_lo_signed, Fixed, FRAC_NBITS};

impl ops::Mul for Fixed {
    type Output = Fixed;

    #[inline]
    fn mul(self: Fixed, other: Fixed) -> Fixed {
        let (ans, overflow) = mul_overflow(self.0, other.0, FRAC_NBITS);
        debug_assert!(!overflow, "overflow");
        Fixed(ans)
    }
}

impl ops::Mul<i64> for Fixed {
    type Output = Fixed;

    #[inline]
    fn mul(self: Fixed, other: i64) -> Fixed {
        Fixed(self.0 * other as i128)
    }
}

#[inline]
fn mul_overflow(lhs: i128, rhs: i128, frac_nbits: u32) -> (i128, bool) {
    if frac_nbits == 0 {
        lhs.overflowing_mul(rhs)
    } else {
        let (lh, ll) = hi_lo_signed(lhs);
        let (rh, rl) = hi_lo_signed(rhs);
        let ll_rl = ll.wrapping_mul(rl);
        let lh_rl = lh.wrapping_mul(rl);
        let ll_rh = ll.wrapping_mul(rh);
        let lh_rh = lh.wrapping_mul(rh);

        let col01 = ll_rl as u128;
        let (col01_hi, col01_lo) = hi_lo(col01);
        let partial_col12 = lh_rl + col01_hi as i128;
        let (col12, carry_col3) = carrying_add(partial_col12, ll_rh);
        let (col12_hi, col12_lo) = hi_lo_signed(col12);
        let ans01 = (col12_lo << 64) as u128 + col01_lo;
        let ans23 = lh_rh + col12_hi + (carry_col3 << 64);
        combine_lo_then_shl(ans23, ans01, frac_nbits)
    }
}

#[inline]
fn carrying_add(lhs: i128, rhs: i128) -> (i128, i128) {
    let (sum, overflow) = lhs.overflowing_add(rhs);
    let carry = if overflow {
        if sum < 0 {
            1
        } else {
            -1
        }
    } else {
        0
    };
    (sum, carry)
}

#[inline]
fn combine_lo_then_shl(hi: i128, lo: u128, shift: u32) -> (i128, bool) {
    if shift == 128 {
        (hi, false)
    } else if shift == 0 {
        let ans = lo as i128;
        (ans, hi != if ans < 0 { -1 } else { 0 })
    } else {
        let lo = (lo >> shift) as i128;
        let ans = lo | (hi << (128 - shift));
        (ans, hi >> shift != if ans < 0 { -1 } else { 0 })
    }
}
