// adapted from https://gitlab.com/tspiteri/fixed
// Copyright © 2018–2020 Trevor Spiteri (licensed under the Apache License, Version 2.0)
// Modifications Copyright (c) 2018-2020 Crypto.com (licensed under the Apache License, Version 2.0)

use core::{
    cmp::{self, Ordering},
    fmt::{
        Alignment, Binary, Debug, Display, Formatter, LowerHex, Octal, Result as FmtResult,
        UpperHex,
    },
    str,
};

use super::{neg_abs, Fixed, FRAC_NBITS, MSB, NBITS};

// We need 130 bytes: 128 digits, one radix point, one leading zero.
//
// The leading zero has two purposes:
//
//  1. If there are no integer digits, we still want to start with "0.".
//  2. If rounding causes a carry, we can overflow into this extra zero.
//
// In the end the layout should be:
//
//   * data[0..int_digits + 1]: integer digits with potentially one extra zero
//   * data[int_digits + 1..int_digits + 2]: '.'
//   * data[int_digits + 2..int_digits + frac_digits + 2]: fractional digits
struct Buffer {
    int_digits: usize,
    frac_digits: usize,
    data: [u8; 130],
}

impl Buffer {
    fn new() -> Buffer {
        Buffer {
            int_digits: 0,
            frac_digits: 0,
            data: [0; 130],
        }
    }

    // Do not combine with new to avoid copying data, otherwise the
    // buffer will be created, modified with the '.', then copied.
    fn set_len(&mut self, int_digits: u32, frac_digits: u32) {
        assert!(int_digits + frac_digits < 130, "out of bounds");
        self.int_digits = int_digits as usize;
        self.frac_digits = frac_digits as usize;
        self.data[1 + self.int_digits] = b'.';
    }

    // does not include leading zero
    fn int(&mut self) -> &mut [u8] {
        let begin = 1;
        let end = begin + self.int_digits;
        &mut self.data[begin..end]
    }

    fn frac(&mut self) -> &mut [u8] {
        let begin = 1 + self.int_digits + 1;
        let end = begin + self.frac_digits;
        &mut self.data[begin..end]
    }

    fn finish(
        &mut self,
        radix: Radix,
        is_neg: bool,
        frac_rem_cmp_msb: Ordering,
        fmt: &mut Formatter,
    ) -> FmtResult {
        self.round_and_trim(radix.max(), frac_rem_cmp_msb);
        self.encode_digits(radix == Radix::UpHex);
        self.pad_and_print(is_neg, radix.prefix(), fmt)
    }

    fn round_and_trim(&mut self, max: u8, frac_rem_cmp_msb: Ordering) {
        let len = if self.frac_digits > 0 {
            self.int_digits + self.frac_digits + 2
        } else {
            self.int_digits + 1
        };

        let round_up = frac_rem_cmp_msb == Ordering::Greater
            || frac_rem_cmp_msb == Ordering::Equal && is_odd(self.data[len - 1]);
        if round_up {
            for b in self.data[0..len].iter_mut().rev() {
                if *b < max {
                    *b += 1;
                    break;
                }
                if *b == b'.' {
                    debug_assert!(self.frac_digits == 0);
                    continue;
                }
                *b = 0;
                if self.frac_digits > 0 {
                    self.frac_digits -= 1;
                }
            }
        } else {
            let mut trim = 0;
            for b in self.frac().iter().rev() {
                if *b != 0 {
                    break;
                }
                trim += 1;
            }
            self.frac_digits -= trim;
        }
    }

    fn encode_digits(&mut self, upper: bool) {
        for digit in self.data[..self.int_digits + self.frac_digits + 2].iter_mut() {
            if *digit < 10 {
                *digit += b'0';
            } else if *digit < 16 {
                *digit += if upper { b'A' - 10 } else { b'a' - 10 };
            }
        }
    }

    fn pad_and_print(&self, is_neg: bool, maybe_prefix: &str, fmt: &mut Formatter) -> FmtResult {
        use core::fmt::Write;

        let sign = if is_neg {
            "-"
        } else if fmt.sign_plus() {
            "+"
        } else {
            ""
        };
        let prefix = if fmt.alternate() { maybe_prefix } else { "" };

        // For numbers with no significant integer bits:
        //   * data starts  with "0." and begin = 0.
        //
        // For numbers with some significant integer bits, data can have:
        //   * no leading zeros => begin = 0
        //   * one leading zero => begin = 1
        //   * two leading zeros => begin = 2
        //
        // Two leading zeros can happen for decimal only. For example
        // with four significant integer bits, we could get anything
        // between 8 and 15, so two decimal digits are allocated apart
        // from the initial padding zero. This means that for 8, data
        // would begin as "008.", and begin = 2.
        let abs_begin = if self.data[0] != b'0' || self.data[1] == b'.' {
            0
        } else if self.data[1] == b'0' {
            2
        } else {
            1
        };
        let end_zeros = fmt.precision().map(|x| x - self.frac_digits).unwrap_or(0);
        let abs_end = if self.frac_digits > 0 {
            self.int_digits + self.frac_digits + 2
        } else if end_zeros > 0 {
            self.int_digits + 2
        } else {
            self.int_digits + 1
        };

        let req_width = sign.len() + prefix.len() + abs_end - abs_begin + end_zeros;
        let pad = fmt
            .width()
            .and_then(|w| w.checked_sub(req_width))
            .unwrap_or(0);
        let (pad_left, pad_zeros, pad_right) = if fmt.sign_aware_zero_pad() {
            (0, pad, 0)
        } else {
            match fmt.align() {
                Some(Alignment::Left) => (0, 0, pad),
                Some(Alignment::Center) => (pad / 2, 0, pad - pad / 2),
                None | Some(Alignment::Right) => (pad, 0, 0),
            }
        };
        let fill = fmt.fill();

        for _ in 0..pad_left {
            fmt.write_char(fill)?;
        }
        fmt.write_str(sign)?;
        fmt.write_str(prefix)?;
        for _ in 0..pad_zeros {
            fmt.write_char('0')?;
        }
        fmt.write_str(str::from_utf8(&self.data[abs_begin..abs_end]).unwrap())?;
        for _ in 0..end_zeros {
            fmt.write_char('0')?;
        }
        for _ in 0..pad_right {
            fmt.write_char(fill)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Radix {
    Bin,
    Oct,
    LowHex,
    UpHex,
    Dec,
}
impl Radix {
    fn digit_bits(self) -> u32 {
        match self {
            Radix::Bin => 1,
            Radix::Oct => 3,
            Radix::LowHex => 4,
            Radix::UpHex => 4,
            Radix::Dec => 4,
        }
    }
    fn max(self) -> u8 {
        match self {
            Radix::Bin => 1,
            Radix::Oct => 7,
            Radix::LowHex => 15,
            Radix::UpHex => 15,
            Radix::Dec => 9,
        }
    }
    fn prefix(self) -> &'static str {
        match self {
            Radix::Bin => "0b",
            Radix::Oct => "0o",
            Radix::LowHex => "0x",
            Radix::UpHex => "0x",
            Radix::Dec => "",
        }
    }
}

#[inline]
fn is_odd(n: u8) -> bool {
    n & 1 != 0
}

fn write_int(mut num: u128, radix: Radix, _nbits: u32, buf: &mut Buffer) {
    // if $attempt_half && nbits < $U::NBITS / 2 {
    //     return (self as $H).write_int(radix, nbits, buf);
    // }
    let digit_bits = radix.digit_bits();
    let mask = radix.max();
    for b in buf.int().iter_mut().rev() {
        debug_assert!(num != 0);
        *b = (num as u8) & mask;
        num >>= digit_bits;
    }
    debug_assert!(num == 0);
}

fn write_frac(mut num: u128, radix: Radix, _nbits: u32, buf: &mut Buffer) -> Ordering {
    // if $attempt_half && nbits < $U::NBITS / 2 {
    //     return ((self >> ($U::NBITS / 2)) as $H).write_frac(radix, nbits, buf);
    // }
    let digit_bits = radix.digit_bits();
    let compl_digit_bits = NBITS - digit_bits;
    for b in buf.frac().iter_mut() {
        debug_assert!(num != 0);
        *b = (num >> compl_digit_bits) as u8;
        num <<= digit_bits;
    }
    num.cmp(&MSB)
}

fn write_int_dec(mut num: u128, _nbits: u32, buf: &mut Buffer) {
    // if $attempt_half && nbits < $U::NBITS / 2 {
    //     return (self as $H).write_int_dec(nbits, buf);
    // }
    for b in buf.int().iter_mut().rev() {
        *b = (num % 10) as u8;
        num /= 10;
    }
    debug_assert!(num == 0);
}

fn write_frac_dec(mut num: u128, nbits: u32, auto_prec: bool, buf: &mut Buffer) -> Ordering {
    // if $attempt_half && nbits < $U::NBITS / 2 {
    //     return ((self >> ($U::NBITS / 2)) as $H).write_frac_dec(nbits, auto_prec, buf);
    // }

    // add_5 is to add rounding when all bits are used
    let (mut tie, mut add_5) = if nbits == NBITS {
        (0, true)
    } else {
        (MSB >> nbits, false)
    };
    let mut trim_to = None;
    for (i, b) in buf.frac().iter_mut().enumerate() {
        *b = mul10_assign(&mut num);

        // Check if very close to zero, to avoid things like 0.19999999 and 0.20000001.
        // This takes place even if we have a precision.
        if num < 10 || num.wrapping_neg() < 10 {
            trim_to = Some(i + 1);
            break;
        }

        if auto_prec {
            // tie might overflow in last iteration when i = frac_digits - 1,
            // but it has no effect as all it can do is set trim_to = Some(i + 1)
            mul10_assign(&mut tie);
            if add_5 {
                tie += 5;
                add_5 = false;
            }
            if num < tie || num.wrapping_neg() < tie {
                trim_to = Some(i + 1);
                break;
            }
        }
    }
    if let Some(trim_to) = trim_to {
        buf.frac_digits = trim_to;
    }
    num.cmp(&MSB)
}

fn fmt_dec((neg, abs): (bool, u128), frac_nbits: u32, fmt: &mut Formatter) -> FmtResult {
    let (int, frac) = if frac_nbits == 0 {
        (abs, 0)
    } else if frac_nbits == NBITS {
        (0, abs)
    } else {
        (abs >> frac_nbits, abs << (NBITS - frac_nbits))
    };
    let int_used_nbits = NBITS - int.leading_zeros();
    let int_digits = ceil_log10_2_times(int_used_nbits);
    let frac_used_nbits = NBITS - frac.trailing_zeros();
    let (frac_digits, auto_prec) = if let Some(precision) = fmt.precision() {
        // frac_used_nbits fits in usize, but precision might wrap to 0 in u32
        (cmp::min(frac_used_nbits as usize, precision) as u32, false)
    } else {
        (ceil_log10_2_times(frac_nbits), true)
    };

    let mut buf = Buffer::new();
    buf.set_len(int_digits, frac_digits);
    write_int_dec(int, int_used_nbits, &mut buf);
    let frac_rem_cmp_msb = write_frac_dec(frac, frac_nbits, auto_prec, &mut buf);
    buf.finish(Radix::Dec, neg, frac_rem_cmp_msb, fmt)
}

fn fmt_radix2(
    (neg, abs): (bool, u128),
    frac_nbits: u32,
    radix: Radix,
    fmt: &mut Formatter,
) -> FmtResult {
    let (int, frac) = if frac_nbits == 0 {
        (abs, 0)
    } else if frac_nbits == NBITS {
        (0, abs)
    } else {
        (abs >> frac_nbits, abs << (NBITS - frac_nbits))
    };
    let digit_bits = radix.digit_bits();
    let int_used_nbits = NBITS - int.leading_zeros();
    let int_digits = (int_used_nbits + digit_bits - 1) / digit_bits;
    let frac_used_nbits = NBITS - frac.trailing_zeros();
    let mut frac_digits = (frac_used_nbits + digit_bits - 1) / digit_bits;
    if let Some(precision) = fmt.precision() {
        // frac_digits fits in usize, but precision might wrap to 0 in u32
        frac_digits = cmp::min(frac_digits as usize, precision) as u32;
    }

    let mut buf = Buffer::new();
    buf.set_len(int_digits, frac_digits);
    write_int(int, radix, int_used_nbits, &mut buf);
    // for bin, oct, hex, we can simply pass frac_used_bits to write_frac
    let frac_rem_cmp_msb = write_frac(frac, radix, frac_used_nbits, &mut buf);
    buf.finish(radix, neg, frac_rem_cmp_msb, fmt)
}

impl Display for Fixed {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        fmt_dec(neg_abs(self.0), FRAC_NBITS, f)
    }
}

impl Debug for Fixed {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        fmt_dec(neg_abs(self.0), FRAC_NBITS, f)
    }
}

impl Binary for Fixed {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        fmt_radix2(neg_abs(self.0), FRAC_NBITS, Radix::Bin, f)
    }
}

impl Octal for Fixed {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        fmt_radix2(neg_abs(self.0), FRAC_NBITS, Radix::Oct, f)
    }
}

impl LowerHex for Fixed {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        fmt_radix2(neg_abs(self.0), FRAC_NBITS, Radix::LowHex, f)
    }
}

impl UpperHex for Fixed {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        fmt_radix2(neg_abs(self.0), FRAC_NBITS, Radix::UpHex, f)
    }
}

// ceil(i × log_10 2), works for input < 112_816
fn ceil_log10_2_times(int_bits: u32) -> u32 {
    debug_assert!(int_bits < 112_816);
    ((u64::from(int_bits) * 0x4D10_4D43 + 0xFFFF_FFFF) >> 32) as u32
}

#[inline]
fn mul10_assign(num: &mut u128) -> u8 {
    const LO_MASK: u128 = !(!0 << 64);
    let hi = (*num >> 64) * 10;
    let lo = (*num & LO_MASK) * 10;
    // Workaround for https://github.com/rust-lang/rust/issues/63384
    // let (wrapped, overflow) = (hi << 64).overflowing_add(lo);
    // ((hi >> 64) as u8 + u8::from(overflow), wrapped)
    let (hi_lo, hi_hi) = (hi as u64, (hi >> 64) as u64);
    let (lo_lo, lo_hi) = (lo as u64, (lo >> 64) as u64);
    let (wrapped, overflow) = hi_lo.overflowing_add(lo_hi);
    *num = (u128::from(wrapped) << 64) | u128::from(lo_lo);
    hi_hi as u8 + u8::from(overflow)
}
