use fixed::types::I64F64;
use std::iter;
use std::prelude::v1::Vec;

pub type FixedNumber = I64F64;

// https://rosettacode.org/wiki/Continued_fraction#Rust
fn continued_fraction(
    series: (
        impl Iterator<Item = FixedNumber>,
        impl Iterator<Item = FixedNumber>,
    ),
    count: usize,
) -> FixedNumber {
    let (mut a, b) = series;
    let init_a = a.next().unwrap();
    init_a
        + a.zip(b)
            .take(count)
            .collect::<Vec<_>>()
            .iter()
            .rev()
            .fold(FixedNumber::from_num(0), |acc, &(x, y)| y / (x + acc))
}

// https://en.wikipedia.org/wiki/Exponential_function#Continued_fractions_for_ex
fn exp_series(
    x: FixedNumber,
) -> (
    impl Iterator<Item = FixedNumber>,
    impl Iterator<Item = FixedNumber>,
) {
    let it_a = vec![FixedNumber::from_num(1), FixedNumber::from_num(1)]
        .into_iter()
        .chain((2..).map(move |n| x + FixedNumber::from_num(n)));
    let it_b = iter::once(1).chain((1..).map(|n| -n)).map(move |n| x * n);
    (it_a, it_b)
}

/// Compute exponencial function with continued fraction method
pub fn exp(x: FixedNumber) -> FixedNumber {
    continued_fraction(exp_series(x), 100)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::quickcheck;
    use std::f64::consts::E;

    quickcheck! {
        fn check_exp_error(i: u64) -> bool {
            let x = FixedNumber::from_num(i) / FixedNumber::from_num(10);
            let a = E.powf(x.to_num::<f64>());
            let b = exp(x).to_num::<f64>();
            let err = (a - b).abs();
            err < 0.000_000_000_1_f64
        }
    }
}
