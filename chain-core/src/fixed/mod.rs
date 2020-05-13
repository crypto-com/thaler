//! For computing monetary expansion formula, we need signed fixed point arithmetic with operations
/// of `add/sub/mul/div`.
///
/// - Signed
/// - The integral part big enough for `u64`
///
/// We choose binary fixed point representation with `i128` and scale factor `2 ^ 63`, or `I64F63`.
///
/// ## `add`/`sub`
///
/// ```plain
/// Fixed(a) +/- Fixed(b)
/// = a * SCALE +/- b * SCALE
/// = (a +/- b) * SCALE
/// = Fixed(a +/- b)
/// ```
///
/// `add/sub` of `Fixed` is simply `i128` `add/sub`.
mod continued_fraction;
mod display;
mod div;
mod mul;

pub use continued_fraction::monetary_expansion;

use core::convert::TryFrom;
use core::ops;

const FRAC_NBITS: u32 = 63;
const NBITS: u32 = 128;
const MSB: u128 = 1 << (NBITS - 1);

/// fixed point number
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct Fixed(pub(crate) i128);

macro_rules! impl_from_integers {
    ($($ty:tt),*) => {
        $(
            impl From<$ty> for Fixed {
                fn from(n: $ty) -> Fixed {
                    Fixed((n as i128) << FRAC_NBITS)
                }
            }
        )*
    };
}

impl_from_integers! {
    i32, u64, i64
}

impl ops::Neg for Fixed {
    type Output = Fixed;
    fn neg(self: Fixed) -> Fixed {
        Fixed(-self.0)
    }
}

impl ops::Add for Fixed {
    type Output = Fixed;
    fn add(self: Fixed, other: Fixed) -> Fixed {
        Fixed(self.0 + other.0)
    }
}

impl ops::Sub for Fixed {
    type Output = Fixed;
    fn sub(self: Fixed, other: Fixed) -> Fixed {
        Fixed(self.0 - other.0)
    }
}

impl Fixed {
    /// get the sign and integer part
    pub fn neg_abs(self) -> (bool, u64) {
        let (sign, n) = neg_abs(self.0 >> FRAC_NBITS);
        debug_assert!(n <= u64::MAX as u128);
        (sign, n as u64)
    }
}

impl TryFrom<Fixed> for u64 {
    type Error = ();
    fn try_from(n: Fixed) -> Result<Self, Self::Error> {
        let (sign, n) = n.neg_abs();
        if sign {
            Err(())
        } else {
            Ok(n)
        }
    }
}

#[inline]
fn neg_abs(num: i128) -> (bool, u128) {
    if num < 0 {
        (true, num.wrapping_neg() as u128)
    } else {
        (false, num as u128)
    }
}

#[inline]
fn hi_lo_signed(n: i128) -> (i128, i128) {
    (n >> 64, n & !(!0 << 64))
}

#[inline]
fn hi_lo(n: u128) -> (u128, u128) {
    (n >> 64, n & !(!0 << 64))
}

#[cfg(test)]
impl From<Fixed> for f64 {
    fn from(n: Fixed) -> f64 {
        from_to_float_helper(neg_abs(n.0), FRAC_NBITS, 64)
    }
}

#[cfg(test)]
fn from_to_float_helper(val: (bool, u128), frac_bits: u32, int_bits: u32) -> f64 {
    const SIGN_MASK: u64 = 1 << 63;
    const PREC: u32 = 53;
    const WANT_MASK: u64 = (1 << (PREC - 1)) - 1;
    const EXP_MASK: u64 = !(SIGN_MASK | WANT_MASK);
    const EXP_BIAS: i32 = (1 << (64 - PREC - 1)) - 1;
    const EXP_MIN: i32 = 1 - EXP_BIAS;
    const EXP_MAX: i32 = EXP_BIAS;

    let fix_bits = frac_bits + int_bits;

    let bits_sign = if val.0 { 1 << 63 } else { 0 };

    let extra_zeros = 128 - fix_bits;
    let leading_zeros = val.1.leading_zeros() - extra_zeros;
    let signif_bits = fix_bits - leading_zeros;
    if signif_bits == 0 {
        return f64::from_bits(bits_sign);
    }
    // remove leading zeros and implicit one
    let mut mantissa = val.1 << leading_zeros << 1;
    let exponent = int_bits as i32 - 1 - leading_zeros as i32;
    let biased_exponent = if exponent > EXP_MAX {
        return f64::from_bits(EXP_MASK | bits_sign);
    } else if exponent < EXP_MIN {
        let lost_prec = EXP_MIN - exponent;
        if lost_prec as u32 >= (int_bits + frac_bits) {
            mantissa = 0;
        } else {
            // reinsert implicit one
            mantissa = (mantissa >> 1) | !(!0 >> 1);
            mantissa >>= lost_prec - 1;
        }
        0
    } else {
        (exponent + EXP_MAX) as u64
    };
    // check for rounding
    let round_up = (fix_bits >= PREC) && {
        let shift = PREC - 1;
        let mid_bit = !(!0 >> 1) >> (shift + extra_zeros);
        let lower_bits = mid_bit - 1;
        if mantissa & mid_bit == 0 {
            false
        } else if mantissa & lower_bits != 0 {
            true
        } else {
            // round to even
            mantissa & (mid_bit << 1) != 0
        }
    };
    let bits_exp = biased_exponent << (PREC - 1);
    let bits_mantissa = (if fix_bits >= PREC - 1 {
        (mantissa >> (fix_bits - (PREC - 1))) as u64
    } else {
        (mantissa as u64) << (PREC - 1 - fix_bits)
    }) & !(!0 << (PREC - 1));
    let mut bits_exp_mantissa = bits_exp | bits_mantissa;
    if round_up {
        bits_exp_mantissa += 1;
    }
    f64::from_bits(bits_sign | bits_exp_mantissa)
}

#[cfg(test)]
mod tests {
    use fixed::types::I65F63 as AltFixed;
    use quickcheck::quickcheck;
    use std::num::NonZeroU64;

    use super::Fixed;

    quickcheck! {
        fn check_add(a: i64, b: i64) -> bool {
            if let Some(c) = a.checked_add(b) {
                Fixed::from(a) + Fixed::from(b) == Fixed::from(c)
            } else {
                true
            }
        }
        fn check_sub(a: i64, b: i64) -> bool {
            if let Some(c) = a.checked_sub(b) {
                Fixed::from(a) - Fixed::from(b) == Fixed::from(c)
            } else {
                Fixed::from(b) - Fixed::from(a) == Fixed::from(b - a)
            }
        }
        fn check_mul(a: i64, b: i64) -> bool {
            if let Some(c) = a.checked_mul(b) {
                Fixed::from(a) * Fixed::from(b) == Fixed::from(c)
            } else {
                true
            }
        }
        fn check_add_fixed(a: i64, b: i64) -> bool {
            (AltFixed::from_num(a) + AltFixed::from_num(b)).to_string() ==
                (Fixed::from(a) + Fixed::from(b)).to_string()
        }
        fn check_sub_fixed(a: i64, b: i64) -> bool {
            (AltFixed::from_num(a) - AltFixed::from_num(b)).to_string() ==
                (Fixed::from(a) - Fixed::from(b)).to_string()
        }
        fn check_mul_fixed(a: i64, b: i64) -> bool {
            (AltFixed::from_num(a) * AltFixed::from_num(b)).to_string() ==
                (Fixed::from(a) * Fixed::from(b)).to_string()
        }
        fn check_div_fixed(a: i64, b: NonZeroU64) -> bool {
            (AltFixed::from_num(a) / AltFixed::from_num(b.get())).to_string() ==
                (Fixed::from(a) / Fixed::from(b.get())).to_string()
        }
    }

    #[test]
    fn check_display() {
        let f1 = AltFixed::from_num(10);
        let f2 = Fixed::from(10_i64);
        assert_eq!(f1.to_string(), f2.to_string());
    }
}
