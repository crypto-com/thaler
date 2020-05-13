// adapted from https://gitlab.com/tspiteri/fixed
// Copyright © 2018–2020 Trevor Spiteri (licensed under the Apache License, Version 2.0)
// Modifications Copyright (c) 2018 - 2020, Foris Limited (licensed under the Apache License, Version 2.0)

use core::ops;

use super::{hi_lo, neg_abs, Fixed, FRAC_NBITS, NBITS};

impl ops::Div for Fixed {
    type Output = Fixed;

    #[inline]
    fn div(self: Fixed, other: Fixed) -> Fixed {
        let (ans, overflow) = div_overflow(self.0, other.0);
        debug_assert!(!overflow, "overflow");
        Fixed(ans)
    }
}

#[inline]
fn div_overflow(lhs: i128, rhs: i128) -> (i128, bool) {
    if FRAC_NBITS == 0 {
        lhs.overflowing_div(rhs)
    } else {
        let lhs2 = (lhs >> (NBITS - FRAC_NBITS), (lhs << FRAC_NBITS) as u128);

        let (d_neg, d_abs) = neg_abs(rhs);
        let (n_neg, n_abs) = neg_abs2(lhs2);
        let (q, _) = div_rem_from(d_abs, n_abs);
        let quot2 = from_neg_abs(n_neg != d_neg, q);

        let quot = quot2.1 as i128;
        let overflow = quot2.0 != if quot < 0 { -1 } else { 0 };
        (quot, overflow)
    }
}

#[inline]
fn div_rem_from(dividor: u128, dividend: (u128, u128)) -> ((u128, u128), u128) {
    let (mut n1, mut n0, mut d) = (dividend.0, dividend.1, dividor);
    let (mut r, zeros) = normalize(&mut d, &mut n1, &mut n0);

    let (n1_hi, n1_lo) = hi_lo(n1);
    let q1h = div_half(&mut r, d, n1_hi);
    let q1l = div_half(&mut r, d, n1_lo);
    let (n0_hi, n0_lo) = hi_lo(n0);
    let q0h = div_half(&mut r, d, n0_hi);
    let q0l = div_half(&mut r, d, n0_lo);
    ((up_lo(q1h, q1l), up_lo(q0h, q0l)), unnormalize(r, zeros))
}

/// Get sign and abs value of num, the num is composed by `hi * 2^128 + lo`.
#[inline]
fn neg_abs2(num: (i128, u128)) -> (bool, (u128, u128)) {
    if num.0 < 0 {
        match num.1.overflowing_neg() {
            (n, true) => (true, (!num.0 as u128, n)),
            (n, false) => (true, (num.0.wrapping_neg() as u128, n)),
        }
    } else {
        (false, (num.0 as u128, num.1))
    }
}

#[inline]
fn from_neg_abs(neg: bool, abs: (u128, u128)) -> (i128, u128) {
    if neg {
        match abs.1.overflowing_neg() {
            (n, true) => (!abs.0 as i128, n),
            (n, false) => (abs.0.wrapping_neg() as i128, n),
        }
    } else {
        (abs.0 as i128, abs.1)
    }
}

#[inline]
fn normalize(num: &mut u128, n1: &mut u128, n0: &mut u128) -> (u128, u32) {
    assert!(*num != 0, "division by zero");
    let zeros = num.leading_zeros();
    if zeros == 0 {
        (0, 0)
    } else {
        *num <<= zeros;
        let n2 = *n1 >> (NBITS - zeros);
        *n1 = *n1 << zeros | *n0 >> (NBITS - zeros);
        *n0 <<= zeros;
        (n2, zeros)
    }
}

#[inline]
fn unnormalize(num: u128, zeros: u32) -> u128 {
    num >> zeros
}

#[inline]
fn div_half(num: &mut u128, d: u128, next_half: u128) -> u128 {
    let (dh, dl) = hi_lo(d);
    let (mut q, rr) = (*num / dh, *num % dh);
    let m = q * dl;
    *num = up_lo(rr, next_half);
    if *num < m {
        q -= 1;
        *num = match num.overflowing_add(d) {
            (r, false) if r < m => {
                q -= 1;
                r.wrapping_add(d)
            }
            (r, _) => r,
        };
    }
    *num = num.wrapping_sub(m);
    q
}

#[inline]
fn up_lo(hi: u128, lo: u128) -> u128 {
    hi << 64 | lo
}
