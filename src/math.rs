//! Pure-Rust `#![no_std]` floating-point intrinsics and hardware AArch64 instructions.

const LN2_HI: f64 = 6.931_471_803_691_238e-1;
const LN2_LO: f64 = 1.908_214_929_270_587_7e-10;
const INV_LN2: f64 = core::f64::consts::LOG2_E;

const LG1: f64 = 6.666_666_666_666_735e-1;
const LG2: f64 = 3.999_999_999_940_942e-1;
const LG3: f64 = 2.857_142_874_366_239e-1;
const LG4: f64 = 2.222_219_843_214_978_4e-1;
const LG5: f64 = 1.818_357_216_161_805e-1;
const LG6: f64 = 1.531_383_769_920_937_3e-1;
const LG7: f64 = 1.479_819_860_511_658_6e-1;

const EXP_P1: f64 = 1.666_666_666_666_660_2e-1;
const EXP_P2: f64 = -2.777_777_777_701_559_3e-3;
const EXP_P3: f64 = 6.613_756_321_437_934e-5;
const EXP_P4: f64 = -1.653_390_220_546_525_2e-6;
const EXP_P5: f64 = 4.138_136_797_057_238_5e-8;

/// Returns the largest integer less than or equal to `x`.
#[must_use]
#[inline]
pub fn floor(x: f64) -> f64 {
    #[cfg(target_arch = "aarch64")]
    {
        let out: f64;
        // SAFETY: `frintm` is a pure scalar floating-point instruction with no memory side effects.
        unsafe {
            core::arch::asm!(
                "frintm {:d}, {:d}",
                out(vreg) out,
                in(vreg) x,
                options(pure, nomem, nostack),
            );
        }
        out
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        if x.is_nan() || x.is_infinite() || x == 0.0 {
            return x;
        }
        let t = trunc(x);
        if x < t { t - 1.0 } else { t }
    }
}

/// Returns the smallest integer greater than or equal to `x`.
#[must_use]
#[inline]
pub fn ceil(x: f64) -> f64 {
    #[cfg(target_arch = "aarch64")]
    {
        let out: f64;
        // SAFETY: `frintp` is a pure scalar floating-point instruction with no memory side effects.
        unsafe {
            core::arch::asm!(
                "frintp {:d}, {:d}",
                out(vreg) out,
                in(vreg) x,
                options(pure, nomem, nostack),
            );
        }
        out
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        if x.is_nan() || x.is_infinite() || x == 0.0 {
            return x;
        }
        let t = trunc(x);
        if x > t { t + 1.0 } else { t }
    }
}

/// Returns the integer part of `x`, rounding toward zero.
#[must_use]
#[inline]
pub fn trunc(x: f64) -> f64 {
    #[cfg(target_arch = "aarch64")]
    {
        let out: f64;
        // SAFETY: `frintz` is a pure scalar floating-point instruction with no memory side effects.
        unsafe {
            core::arch::asm!(
                "frintz {:d}, {:d}",
                out(vreg) out,
                in(vreg) x,
                options(pure, nomem, nostack),
            );
        }
        out
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let bits = x.to_bits();
        let exp = ((bits >> 52) & 0x7ff) as i32 - 1023;
        if exp < 0 {
            return f64::from_bits(bits & (1u64 << 63));
        }
        if exp >= 52 {
            return x;
        }
        let mask = (1u64 << (52 - exp)) - 1;
        f64::from_bits(bits & !mask)
    }
}

/// Computes the natural logarithm $\ln(x)$ using the FDLIBM minimax approximation.
#[must_use]
pub fn ln(x: f64) -> f64 {
    if x.is_nan() || x < 0.0 {
        return f64::NAN;
    }
    if x == 0.0 {
        return f64::NEG_INFINITY;
    }
    if x == f64::INFINITY {
        return f64::INFINITY;
    }
    if x == 1.0 {
        return 0.0;
    }

    let mut ux = x.to_bits();
    let mut k = 0i32;
    if (ux >> 52) == 0 {
        // Subnormal input: scale up by 2^52.
        ux = (x * ((1u64 << 52) as f64)).to_bits();
        k -= 52;
    }

    k += ((ux >> 52) as i32) - 1023;
    let mant_hi = ((ux >> 32) as u32) & 0x000f_ffff;
    // Center reduced mantissa around [sqrt(2)/2, sqrt(2)].
    let offset = (mant_hi + 0x95f64) & 0x0010_0000;
    let m_bits = (ux & 0x000f_ffff_ffff_ffff) | (((offset ^ 0x3ff0_0000) as u64) << 32);
    k += (offset >> 20) as i32;

    let f = f64::from_bits(m_bits) - 1.0;
    let s = f / (2.0 + f);
    let z = s * s;
    let w = z * z;
    let t1 = w * (LG2 + w * (LG4 + w * LG6));
    let t2 = z * (LG1 + w * (LG3 + w * (LG5 + w * LG7)));
    let r = t2 + t1;
    let hfsq = 0.5 * f * f;
    let dk = k as f64;

    dk * LN2_HI - ((hfsq - (s * (hfsq + r) + dk * LN2_LO)) - f)
}

/// Computes $e^x$ using the FDLIBM range reduction and Remez rational approximation.
fn exp(x: f64) -> f64 {
    if x.is_nan() {
        return f64::NAN;
    }
    if x > 709.782_712_893_384 {
        return f64::INFINITY;
    }
    if x < -745.133_219_101_941_1 {
        return 0.0;
    }
    if x == 0.0 {
        return 1.0;
    }

    let k = if x >= 0.0 {
        floor(x * INV_LN2 + 0.5) as i32
    } else {
        ceil(x * INV_LN2 - 0.5) as i32
    };
    let dk = k as f64;
    let hi = x - dk * LN2_HI;
    let lo = dk * LN2_LO;
    let r = hi - lo;
    let z = r * r;
    let c = r - z * (EXP_P1 + z * (EXP_P2 + z * (EXP_P3 + z * (EXP_P4 + z * EXP_P5))));
    let y = 1.0 - ((lo - (r * c) / (2.0 - c)) - hi);

    scale_pow2(y, k)
}

#[inline]
fn scale_pow2(y: f64, k: i32) -> f64 {
    if (-1021..=1023).contains(&k) {
        return y * f64::from_bits(((k + 1023) as u64) << 52);
    }
    if k == 1024 {
        return (y * f64::from_bits(2046u64 << 52)) * 2.0;
    }
    // Subnormal range (k < -1021): scale in two steps.
    let k1 = -1022;
    let k2 = k - k1;
    (y * f64::from_bits(((k1 + 1023) as u64) << 52)) * f64::from_bits(((k2 + 1023) as u64) << 52)
}

/// classifies finite `y`: `0` = non-integer, `1` = odd integer, `2` = even integer.
#[inline]
fn classify_integer(y: f64) -> u8 {
    let ay = if y < 0.0 { -y } else { y };
    if ay >= 9_007_199_254_740_992.0 {
        // |y| >= 2^53: all representable IEEE-754 f64 values are even integers.
        return 2;
    }
    let t = trunc(ay);
    if t != ay {
        return 0;
    }
    let n = t as u64;
    if (n & 1) == 1 { 1 } else { 2 }
}

#[inline]
fn powi_small(mut base: f64, exp_val: i32) -> f64 {
    let mut e = if exp_val < 0 {
        base = 1.0 / base;
        (-exp_val) as u32
    } else {
        exp_val as u32
    };
    let mut acc = 1.0;
    while e != 0 {
        if (e & 1) != 0 {
            acc *= base;
        }
        e >>= 1;
        if e != 0 {
            base *= base;
        }
    }
    acc
}

/// Computes $x^y$ following IEEE-754 special-case rules.
#[must_use]
pub fn powf(x: f64, y: f64) -> f64 {
    if y == 0.0 || x == 1.0 {
        return 1.0;
    }
    if x.is_nan() || y.is_nan() {
        return f64::NAN;
    }

    if y.is_infinite() {
        let ax = if x < 0.0 { -x } else { x };
        if ax == 1.0 {
            return 1.0;
        }
        return if (ax > 1.0) == (y > 0.0) {
            f64::INFINITY
        } else {
            0.0
        };
    }

    let y_int = classify_integer(y);

    if x.is_infinite() {
        if x > 0.0 {
            return if y > 0.0 { f64::INFINITY } else { 0.0 };
        }
        return if y > 0.0 {
            if y_int == 1 {
                f64::NEG_INFINITY
            } else {
                f64::INFINITY
            }
        } else if y_int == 1 {
            -0.0
        } else {
            0.0
        };
    }

    if x == 0.0 {
        let neg_zero = (x.to_bits() >> 63) != 0;
        return if y > 0.0 {
            if neg_zero && y_int == 1 { -0.0 } else { 0.0 }
        } else if neg_zero && y_int == 1 {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        };
    }

    let mut sign = 1.0;
    let ax = if x < 0.0 {
        if y_int == 0 {
            return f64::NAN;
        }
        if y_int == 1 {
            sign = -1.0;
        }
        -x
    } else {
        x
    };

    if y_int != 0 && (-64.0..=64.0).contains(&y) {
        return sign * powi_small(ax, y as i32);
    }

    sign * exp(y * ln(ax))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rel_err(actual: f64, expected: f64) -> f64 {
        let diff = if actual >= expected {
            actual - expected
        } else {
            expected - actual
        };
        diff / (if expected >= 0.0 { expected } else { -expected })
    }

    #[test]
    fn rounding_and_sqrt_exact_and_edge_cases() {
        assert_eq!(floor(2.7), 2.0);
        assert_eq!(floor(-2.7), -3.0);
        assert_eq!(floor(3.0), 3.0);
        assert_eq!(floor(-3.0), -3.0);
        assert_eq!(floor(0.0).to_bits(), 0.0f64.to_bits());
        assert_eq!(floor(-0.0).to_bits(), (-0.0f64).to_bits());
        assert!(floor(f64::NAN).is_nan());
        assert_eq!(floor(f64::INFINITY), f64::INFINITY);
        assert_eq!(floor(f64::NEG_INFINITY), f64::NEG_INFINITY);

        assert_eq!(ceil(2.3), 3.0);
        assert_eq!(ceil(-2.3), -2.0);
        assert_eq!(ceil(4.0), 4.0);
        assert_eq!(ceil(-4.0), -4.0);
        assert_eq!(ceil(-0.0).to_bits(), (-0.0f64).to_bits());
        assert!(ceil(f64::NAN).is_nan());

        assert_eq!(trunc(2.9), 2.0);
        assert_eq!(trunc(-2.9), -2.0);
        assert_eq!(trunc(-0.5).to_bits(), (-0.0f64).to_bits());
        assert!(trunc(f64::NAN).is_nan());
    }

    #[test]
    fn ln_exp_powf_accuracy_and_ieee_special_cases() {
        assert_eq!(ln(1.0), 0.0);
        assert_eq!(ln(0.0), f64::NEG_INFINITY);
        assert_eq!(ln(-0.0), f64::NEG_INFINITY);
        assert!(ln(-1.0).is_nan());
        assert!(ln(f64::NAN).is_nan());
        assert_eq!(ln(f64::INFINITY), f64::INFINITY);

        assert!(rel_err(ln(core::f64::consts::E), 1.0) < 1e-15);
        assert!(rel_err(ln(2.0), core::f64::consts::LN_2) < 1e-15);
        assert!(rel_err(ln(10.0), core::f64::consts::LN_10) < 1e-15);
        assert!(rel_err(ln(0.5), -core::f64::consts::LN_2) < 1e-15);

        assert_eq!(exp(0.0), 1.0);
        assert_eq!(exp(800.0), f64::INFINITY);
        assert_eq!(exp(-800.0), 0.0);
        assert!(exp(f64::NAN).is_nan());
        assert!(rel_err(exp(1.0), core::f64::consts::E) < 1e-15);
        assert!(rel_err(exp(core::f64::consts::LN_2 * 10.0), 1024.0) < 1e-14);

        assert_eq!(powf(2.0, 10.0), 1024.0);
        assert_eq!(powf(-2.0, 3.0), -8.0);
        assert_eq!(powf(-2.0, 4.0), 16.0);
        assert!(powf(-2.0, 0.5).is_nan());
        assert_eq!(powf(f64::NAN, 0.0), 1.0);
        assert_eq!(powf(1.0, f64::NAN), 1.0);
        assert_eq!(powf(1.0, f64::INFINITY), 1.0);
        assert_eq!(powf(-1.0, f64::INFINITY), 1.0);
        assert_eq!(powf(0.0, 3.0).to_bits(), 0.0f64.to_bits());
        assert_eq!(powf(-0.0, 3.0).to_bits(), (-0.0f64).to_bits());
        assert_eq!(powf(-0.0, 4.0).to_bits(), 0.0f64.to_bits());
        assert_eq!(powf(0.0, -2.0), f64::INFINITY);
        assert_eq!(powf(-0.0, -3.0), f64::NEG_INFINITY);
        assert!(rel_err(powf(9.0, 0.5), 3.0) < 1e-14);
        assert!(rel_err(powf(core::f64::consts::E, 2.5), exp(2.5)) < 1e-14);
    }
}
