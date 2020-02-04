use std::iter;
use std::prelude::v1::Vec;

use crate::init::coin::Coin;
use crate::tx::fee::Milli;
pub use fixed::types::I65F63 as Fixed;

// with I65F63, exp2(EXP_LOWER_BOUND, 1) == 0
const EXP_LOWER_BOUND: i32 = -30;

/// Given `series=([a1, a2, a3, ...], [b1, b2, ...])` and `count=2`
/// Compute: `a1 + b1 / (a2 + b2 / (a3 + 0))`
fn continued_fraction(
    series: (impl Iterator<Item = Fixed>, impl Iterator<Item = Fixed>),
    count: usize,
) -> Fixed {
    let (mut a, b) = series;
    let init_a = a.next().unwrap();
    init_a
        + a.zip(b)
            .take(count)
            .collect::<Vec<_>>()
            .iter()
            .rev()
            .fold(Fixed::from_num(0), |acc, &(x, y)| y / (x + acc))
}

/// Continued fraction series for `exp(x / y)`
/// https://en.wikipedia.org/wiki/Exponential_function#Continued_fractions_for_ex
/// ```plain
/// series_a: 1, 2y-x, 6y,  10y, 14y, ...
/// series_b:    2x,   x^2, x^2, x^2, ...
/// ```
fn exp2_series(x: Fixed, y: Fixed) -> (impl Iterator<Item = Fixed>, impl Iterator<Item = Fixed>) {
    let x2 = x * x;
    let series_a = vec![Fixed::from_num(1), y * 2 - x]
        .into_iter()
        .chain((0..).map(move |i| y * (i * 4 + 6)));
    let series_b = iter::once(2 * x).chain(iter::repeat(x2));
    (series_a, series_b)
}

/// Compute `exp(x / y)` with continued fraction method
pub fn exp2(x: Fixed, y: Fixed) -> Fixed {
    continued_fraction(exp2_series(x, y), 25)
}

/// Continued fraction series for `ln(1 + x / y)`
/// https://en.wikipedia.org/wiki/Natural_logarithm#Continued_fractions
///
/// ```plain
/// series_a: 0, 2y+x, 3(2y+x), 5(2y+x), 7(2y+x), ...
/// series_b:    2x,   (1x)^2,  (2x)^2,  (3x)^2,  ...
/// ```
fn log2_series(x: Fixed, y: Fixed) -> (impl Iterator<Item = Fixed>, impl Iterator<Item = Fixed>) {
    let n1 = 2 * y + x;
    let x2 = x * x;
    let series_a = iter::once(Fixed::from_num(0)).chain((1..).step_by(2).map(move |i| n1 * i));
    let series_b = iter::once(2 * x).chain((1..).map(move |i| -x2 * (i * i)));
    (series_a, series_b)
}

/// Compute `ln(1 + x / y)` with continued fraction method
pub fn log2(x: Fixed, y: Fixed) -> Fixed {
    continued_fraction(log2_series(x, y), 10)
}

/// Compute newly released coins for rewards distribution.
/// [Docs for the formula](https://crypto-com.github.io/getting-started/staking.html#monetary-expansion)
pub fn monetary_expansion(staking: Coin, tau: u64, r0: Milli, period: u64) -> Coin {
    assert!(tau > 0 && tau <= 100_00000000_00000000_u64);

    let r0 = Fixed::from_num(r0.as_millis());
    let period = Fixed::from_num(period);

    let staking = Fixed::from_num(u64::from(staking));
    let tau = Fixed::from_num(tau);

    let base = Fixed::from_num(10000000_00000000_u64);
    let year = Fixed::from_num(365 * 24 * 60 * 60);

    let staking_ = staking / base;
    let tau_ = tau / base;
    let n0 = if -staking_ / tau_ < Fixed::from_num(EXP_LOWER_BOUND) {
        exp2(Fixed::from_num(EXP_LOWER_BOUND), Fixed::from_num(1))
    } else {
        exp2(-staking_, tau_)
    };
    let n1 = log2(n0 * r0, Fixed::from_num(1000));
    let n2 = exp2(n1 * period, year);
    let n3 = staking * (n2 - Fixed::from_num(1));
    // drop fraction part, no wrap
    let n4 = n3.checked_to_num::<u64>().unwrap();
    Coin::new(n4 - n4 % 10000).unwrap()
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;
    use std::f64::consts::E;

    use super::*;
    use quickcheck::quickcheck;

    const MIN_ERROR: f64 = 0.000_000_001;

    fn exp_error(x: Fixed, y: Fixed) -> f64 {
        let a = E.powf((x / y).to_num::<f64>());
        let b = exp2(x, y).to_num::<f64>();
        (a - b).abs()
    }

    fn log_error(x: Fixed, y: Fixed) -> f64 {
        let a = (1. + (x / y).to_num::<f64>()).ln();
        let b = log2(x, y).to_num::<f64>();
        (a - b).abs()
    }

    #[test]
    fn check_exp_lower_bound() {
        let err = exp_error(Fixed::from_num(EXP_LOWER_BOUND), Fixed::from_num(1));
        assert!(err < MIN_ERROR);
    }

    quickcheck! {
        fn check_exp_error(i: u64) -> bool {
            let err = exp_error(Fixed::from_num(i), Fixed::from_num(10));
            err < MIN_ERROR
        }
    }

    #[test]
    fn check_log_large_error() {
        let err = log_error(Fixed::from_num(100), Fixed::from_num(100));
        assert!(err < MIN_ERROR);
    }

    #[test]
    fn check_log_edge_case() {
        let err = log_error(
            exp2(Fixed::from_num(EXP_LOWER_BOUND), Fixed::from_num(1)),
            Fixed::from_num(1),
        );
        assert!(err < MIN_ERROR);
    }

    quickcheck! {
        fn check_log_error(i: u64) -> bool {
            let err = log_error(Fixed::from_num(i % 100), Fixed::from_num(100));
            err < MIN_ERROR
        }
    }

    fn monetary_expansion_f64(staking: Coin, tau: u64, r0: Milli, period: u64) -> Coin {
        let staking = u64::from(staking) as f64;
        let tau = tau as f64;
        let r0 = r0.as_millis() as f64;
        let period = period as f64;
        let year = (365 * 24 * 60 * 60) as f64;

        let n0 = E.powf(-staking / tau);
        let n1 = (1. + r0 * n0 / 1000.).ln();
        let n2 = E.powf(period * n1 / year);
        let n3 = staking * (n2 - 1.);
        // drop fraction part, no wrap.
        let n4 = u64::try_from(n3 as i64).unwrap();
        Coin::new(n4 - n4 % 10000).unwrap()
    }

    /// Check the result against float point arithemetic.
    fn check_monetory_expansion(staking: Coin, tau: u64, r0: Milli, period: u64) -> Coin {
        let coins = monetary_expansion(staking, tau, r0, period);
        let coinsf = monetary_expansion_f64(staking, tau, r0, period);
        assert_eq!(coins, coinsf);
        coins
    }

    #[test]
    fn check_monetory_expansion_normal() {
        let coins = check_monetory_expansion(
            Coin::new(1_00000000_00000000_u64).unwrap(),
            1_45000000_00000000_u64,
            Milli::new(0, 500),
            86400,
        );
        assert_eq!(u64::from(coins), 61345_63860000);
    }

    #[test]
    fn check_monetory_expansion_edge_cases() {
        // staking: [1, 100_00000000_00000000]
        // tau: [1, 100_00000000_00000000]
        // r0: [0, ...]
        // period: [0, ...]
        println!(
            "coins: {}",
            check_monetory_expansion(Coin::one(), 1, Milli::new(0, 500), 86400)
        );
        println!(
            "coins: {}",
            check_monetory_expansion(
                Coin::one(),
                100_00000000_00000000_u64,
                Milli::new(0, 500),
                86400
            )
        );
        println!(
            "coins: {}",
            check_monetory_expansion(Coin::max(), 1, Milli::new(0, 500), 86400)
        );
        println!(
            "coins: {}",
            check_monetory_expansion(
                Coin::max(),
                100_00000000_00000000,
                Milli::integral(1),
                365 * 24 * 60 * 60
            )
        );
        println!(
            "coins: {}",
            check_monetory_expansion(Coin::max(), 100_00000000_00000000, Milli::new(0, 1), 1)
        );
        println!(
            "coins: {}",
            check_monetory_expansion(Coin::max(), 100_00000000_00000000, Milli::new(0, 0), 0)
        );

        // more than one year period
        println!(
            "coins: {}",
            check_monetory_expansion(
                Coin::max(),
                100_00000000_00000000,
                Milli::new(0, 500),
                3 * 365 * 24 * 60 * 60
            )
        );

        // more than 1000 r0 value
        println!(
            "coins: {}",
            check_monetory_expansion(
                Coin::max(),
                100_00000000_00000000,
                Milli::new(1, 500),
                24 * 60 * 60
            )
        );
    }
}
