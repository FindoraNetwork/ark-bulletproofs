use ark_ff::{
    biginteger::{BigInt, BigInteger320},
    fields::{Fp320, Fp320Parameters, FpParameters},
    FftParameters,
};

pub type Fr = Fp320<FrParameters>;

pub struct FrParameters;

impl Fp320Parameters for FrParameters {}

impl FftParameters for FrParameters {
    type BigInt = BigInteger320;
    const TWO_ADICITY: u32 = 1;
    const TWO_ADIC_ROOT_OF_UNITY: Self::BigInt = BigInt::new([
        0xfffffffefffffc2f,
        0xfffffffefffffc2e,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0x0,
    ]);
}

impl FpParameters for FrParameters {
    /// MODULUS = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
    ///         = 115792089237316195423570985008687907853269984665640564039457584007908834671663
    #[rustfmt::skip]
    const MODULUS: BigInteger320 = BigInt::new([
        0xfffffffefffffc2f,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0x0,
    ]);

    const MODULUS_BITS: u32 = 256;

    const CAPACITY: u32 = Self::MODULUS_BITS - 1;

    const REPR_SHAVE_BITS: u32 = 64;

    /// Let `M` be the power of 2^64 nearest to `Self::MODULUS_BITS`. Then
    /// `R = M % Self::MODULUS`.
    ///
    /// `M = 2^{320}`.
    /// `R = 79228180536733297607775879168`.
    #[rustfmt::skip]
    const R: BigInteger320 = BigInt::new([
        0x0,
        0x00000001000003d1,
        0x0,
        0x0,
        0x0,
    ]);

    /// `R2 = R^2 % Self::MODULUS`.
    /// `R2 = 6277104591161204917807506269678420775220033090435336372224`.
    #[rustfmt::skip]
    const R2: BigInteger320 = BigInt::new([
        0x0,
        0x0,
        0x000007a2000e90a1,
        0x0000000000000001,
        0x0000000000000000,
    ]);

    /// `INV = -MODULUS^{-1} mod 2^64`.
    /// `INV = 15580212934572586289`.
    const INV: u64 = 0xd838091dd2253531;

    /// GENERATOR = 3
    /// Encoded in Montgomery form, so the value here is
    /// `3 * R % q = 237684541610199892823327637504`
    #[rustfmt::skip]
    const GENERATOR: BigInteger320 = BigInt::new([
        0x0,
        0x300000b73,
        0x0,
        0x0,
        0x0,
    ]);

    #[rustfmt::skip]
    /// `57896044618658097711785492504343953926634992332820282019728792003954417335831`
    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger320 = BigInt::new([
        0xffffffff7ffffe17,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0x7fffffffffffffff,
        0x0,
    ]);

    /// T and T_MINUS_ONE_DIV_TWO, where `MODULUS - 1 = 2^S * T`
    /// For T coprime to 2
    ///
    /// In our case, `S = 1`.
    ///
    /// `T = (MODULUS - 1) / 2^S =`
    /// `57896044618658097711785492504343953926634992332820282019728792003954417335831`
    #[rustfmt::skip]
    const T: BigInteger320 = BigInt::new([
        0xffffffff7ffffe17,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0x0,
    ]);

    /// `(T - 1) / 2 =`
    /// `28948022309329048855892746252171976963317496166410141009864396001977208667915`
    #[rustfmt::skip]
    const T_MINUS_ONE_DIV_TWO: BigInteger320 = BigInt::new([
        0xffffffffbfffff0b,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0x3fffffffffffffff,
        0x0,
    ]);
}

#[cfg(test)]
mod test {
    use crate::curve::canaan::fr::Fr;
    use ark_algebra_test_templates::fields::{field_test, primefield_test};
    use ark_ff::{Field, One, UniformRand, Zero};
    use ark_std::{
        ops::{AddAssign, MulAssign, SubAssign},
        test_rng,
    };

    pub(crate) const ITERATIONS: usize = 5;

    #[test]
    fn test_fr() {
        let mut rng = ark_std::test_rng();
        for _ in 0..ITERATIONS {
            let a: Fr = UniformRand::rand(&mut rng);
            let b: Fr = UniformRand::rand(&mut rng);
            field_test(a, b);
            primefield_test::<Fr>();
        }
    }

    #[test]
    fn test_fr_add_assign() {
        // Test associativity

        let mut rng = test_rng();

        for _ in 0..1000 {
            // Generate a, b, c and ensure (a + b) + c == a + (b + c).
            let a = Fr::rand(&mut rng);
            let b = Fr::rand(&mut rng);
            let c = Fr::rand(&mut rng);

            let mut tmp1 = a;
            tmp1.add_assign(&b);
            tmp1.add_assign(&c);

            let mut tmp2 = b;
            tmp2.add_assign(&c);
            tmp2.add_assign(&a);

            assert_eq!(tmp1, tmp2);
        }
    }

    #[test]
    fn test_fr_sub_assign() {
        let mut rng = test_rng();

        for _ in 0..1000 {
            // Ensure that (a - b) + (b - a) = 0.
            let a = Fr::rand(&mut rng);
            let b = Fr::rand(&mut rng);

            let mut tmp1 = a;
            tmp1.sub_assign(&b);

            let mut tmp2 = b;
            tmp2.sub_assign(&a);

            tmp1.add_assign(&tmp2);
            assert!(tmp1.is_zero());
        }
    }

    #[test]
    fn test_fr_mul_assign() {
        let mut rng = test_rng();

        for _ in 0..1000 {
            // Ensure that (a * b) * c = a * (b * c)
            let a = Fr::rand(&mut rng);
            let b = Fr::rand(&mut rng);
            let c = Fr::rand(&mut rng);

            let mut tmp1 = a;
            tmp1.mul_assign(&b);
            tmp1.mul_assign(&c);

            let mut tmp2 = b;
            tmp2.mul_assign(&c);
            tmp2.mul_assign(&a);

            assert_eq!(tmp1, tmp2);
        }

        for _ in 0..1000 {
            // Ensure that r * (a + b + c) = r*a + r*b + r*c

            let r = Fr::rand(&mut rng);
            let mut a = Fr::rand(&mut rng);
            let mut b = Fr::rand(&mut rng);
            let mut c = Fr::rand(&mut rng);

            let mut tmp1 = a;
            tmp1.add_assign(&b);
            tmp1.add_assign(&c);
            tmp1.mul_assign(&r);

            a.mul_assign(&r);
            b.mul_assign(&r);
            c.mul_assign(&r);

            a.add_assign(&b);
            a.add_assign(&c);

            assert_eq!(tmp1, a);
        }
    }

    #[test]
    fn test_fr_squaring() {
        let mut rng = test_rng();

        for _ in 0..1000 {
            // Ensure that (a * a) = a^2
            let a = Fr::rand(&mut rng);

            let mut tmp = a;
            tmp.square_in_place();

            let mut tmp2 = a;
            tmp2.mul_assign(&a);

            assert_eq!(tmp, tmp2);
        }
    }

    #[test]
    fn test_fr_inverse() {
        assert!(Fr::zero().inverse().is_none());

        let mut rng = test_rng();

        let one = Fr::one();

        for _ in 0..1000 {
            // Ensure that a * a^-1 = 1
            let mut a = Fr::rand(&mut rng);
            let ainv = a.inverse().unwrap();
            a.mul_assign(&ainv);
            assert_eq!(a, one);
        }
    }

    #[test]
    fn test_fr_double_in_place() {
        let mut rng = test_rng();

        for _ in 0..1000 {
            // Ensure doubling a is equivalent to adding a to itself.
            let mut a = Fr::rand(&mut rng);
            let mut b = a;
            b.add_assign(&a);
            a.double_in_place();
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_fr_negate() {
        {
            let a = -Fr::zero();

            assert!(a.is_zero());
        }

        let mut rng = test_rng();

        for _ in 0..1000 {
            // Ensure (a - (-a)) = 0.
            let mut a = Fr::rand(&mut rng);
            let b = -a;
            a.add_assign(&b);

            assert!(a.is_zero());
        }
    }

    #[test]
    fn test_fr_pow() {
        let mut rng = test_rng();

        for i in 0..1000 {
            // Exponentiate by various small numbers and ensure it consists with repeated
            // multiplication.
            let a = Fr::rand(&mut rng);
            let target = a.pow(&[i]);
            let mut c = Fr::one();
            for _ in 0..i {
                c.mul_assign(&a);
            }
            assert_eq!(c, target);
        }

        for _ in 0..1000 {
            // Exponentiating by the modulus should have no effect in a prime field.
            let a = Fr::rand(&mut rng);

            assert_eq!(a, a.pow(Fr::characteristic()));
        }
    }
}
