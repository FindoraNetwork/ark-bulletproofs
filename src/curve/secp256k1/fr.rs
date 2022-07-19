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
    const TWO_ADICITY: u32 = 6;
    const TWO_ADIC_ROOT_OF_UNITY: Self::BigInt = BigInt::new([
        0x0112cb0f605a214a,
        0x92225daffb794500,
        0x7e42003a6ccb6212,
        0x55980b07bc222114,
        0x0,
    ]);
}

impl FpParameters for FrParameters {
    /// MODULUS = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
    ///         = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    #[rustfmt::skip]
    const MODULUS: BigInteger320 = BigInt::new([
        0xbfd25e8cd0364141,
        0xbaaedce6af48a03b,
        0xfffffffffffffffe,
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
    /// `R = 7976748203231275684456616952498544216114824026705293737984`.
    #[rustfmt::skip]
    const R: BigInteger320 = BigInt::new([
        0x0,
        0x402da1732fc9bebf,
        0x4551231950b75fc4,
        0x1,
        0x0,
    ]);

    /// `R2 = R^2 % Self::MODULUS`.
    /// `R2 = 27185382341430777127667013160941942500583767731514336557959633868809832333177`.
    #[rustfmt::skip]
    const R2: BigInteger320 = BigInt::new([
        0x1e004f504dfd7f79,
        0x08fcf59774a052ea,
        0x27c4120fc94e1653,
        0x3c1a6191e5702644,
        0x0
    ]);

    /// `INV = -MODULUS^{-1} mod 2^64`.
    /// `INV = 5408259542528602431`.
    const INV: u64 = 0x4b0dff665588b13f;

    /// GENERATOR = 7
    /// Encoded in Montgomery form, so the value here is
    /// `3 * R % q = 55837237422618929791196318667489809512803768186937056165888`
    #[rustfmt::skip]
    const GENERATOR: BigInteger320 = BigInt::new([
        0x0,
        0xc13f6a264e843739,
        0xe537f5b135039e5d,
        0x8,
        0x0,
    ]);

    #[rustfmt::skip]
    /// `57896044618658097711785492504343953926634992332820282019728792003954417335831`
    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger320 = BigInt::new([
        0xdfe92f46681b20a0,
        0x5d576e7357a4501d,
        0xffffffffffffffff,
        0x7fffffffffffffff,
        0x0
    ]);

    /// T and T_MINUS_ONE_DIV_TWO, where `MODULUS - 1 = 2^S * T`
    /// For T coprime to 2
    ///
    /// In our case, `S = 6`.
    ///
    /// `T = (MODULUS - 1) / 2^S =`
    /// `1809251394333065553493296640760748560200586941860545380978205674086221273349`
    #[rustfmt::skip]
    const T: BigInteger320 = BigInt::new([
        0xeeff497a3340d905,
        0xfaeabb739abd2280,
        0xffffffffffffffff,
        0x03ffffffffffffff,
        0x0
    ]);

    /// `(T - 1) / 2 =`
    /// `904625697166532776746648320380374280100293470930272690489102837043110636674`
    #[rustfmt::skip]
    const T_MINUS_ONE_DIV_TWO: BigInteger320 = BigInt::new([
        0x777fa4bd19a06c82,
        0xfd755db9cd5e9140,
        0xffffffffffffffff,
        0x01ffffffffffffff,
        0x0
    ]);
}

#[cfg(test)]
mod test {
    use crate::curve::secp256k1::fr::Fr;
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
