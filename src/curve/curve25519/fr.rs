use ark_ff::{
    biginteger::{BigInt, BigInteger256},
    fields::{Fp256, Fp256Parameters, FpParameters},
    FftParameters,
};

pub type Fr = Fp256<FrParameters>;

pub struct FrParameters;

impl Fp256Parameters for FrParameters {}

impl FftParameters for FrParameters {
    type BigInt = BigInteger256;
    const TWO_ADICITY: u32 = 2;
    const TWO_ADIC_ROOT_OF_UNITY: Self::BigInt = BigInt::new([
        0x7c790e32b42f0e7d,
        0x4c8ce706a7ae2cc8,
        0xd73823cc921779ad,
        0x5599959893f562a,
    ]);
}

impl FpParameters for FrParameters {
    /// MODULUS = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
    ///         = 7237005577332262213973186563042994240857116359379907606001950938285454250989
    #[rustfmt::skip]
    const MODULUS: BigInteger256 = BigInt::new([
        0x5812631a5cf5d3ed,
        0x14def9dea2f79cd6,
        0x0,
        0x1000000000000000,
    ]);

    const MODULUS_BITS: u32 = 253;

    const CAPACITY: u32 = Self::MODULUS_BITS - 1;

    const REPR_SHAVE_BITS: u32 = 3;

    /// Let `M` be the power of 2^64 nearest to `Self::MODULUS_BITS`. Then
    /// `R = M % Self::MODULUS`.
    ///
    /// `M = 2^{256}`.
    /// `R = 7237005577332262213973186563042994240413239274941949949428319933631315875101`.
    #[rustfmt::skip]
    const R: BigInteger256 = BigInt::new([
        0xd6ec31748d98951d,
        0xc6ef5bf4737dcf70,
        0xfffffffffffffffe,
        0xfffffffffffffff,
    ]);

    /// `R2 = R^2 % Self::MODULUS`.
    /// `R2 = 1627715501170711445284395025044413883736156588369414752970002579683115011841`.
    #[rustfmt::skip]
    const R2: BigInteger256 = BigInt::new([
        0xa40611e3449c0f01,
        0xd00e1ba768859347,
        0xceec73d217f5be65,
        0x399411b7c309a3d
    ]);

    /// `INV = -MODULUS^{-1} mod 2^64`.
    /// `INV = 15183074304973897243`.
    const INV: u64 = 0xd2b51da312547e1b;

    /// GENERATOR = 2
    /// Encoded in Montgomery form, so the value here is
    /// `2 * R % q = 7237005577332262213973186563042994239969362190503992292854688928977177499213`
    #[rustfmt::skip]
    const GENERATOR: BigInteger256 = BigInt::new([
        0x55c5ffcebe3b564d,
        0x78ffbe0a4404020b,
        0xfffffffffffffffd,
        0xfffffffffffffff,
    ]);

    #[rustfmt::skip]
    /// `3618502788666131106986593281521497120428558179689953803000975469142727125494`
    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger256 = BigInt::new([
        0x2c09318d2e7ae9f6,
        0xa6f7cef517bce6b,
        0x0,
        0x800000000000000,
    ]);

    /// T and T_MINUS_ONE_DIV_TWO, where `MODULUS - 1 = 2^S * T`
    /// For T coprime to 2
    ///
    /// In our case, `S = 2`.
    ///
    /// `T = (MODULUS - 1) / 2^S =`
    /// `1809251394333065553493296640760748560214279089844976901500487734571363562747`
    #[rustfmt::skip]
    const T: BigInteger256 = BigInt::new([
        0x960498c6973d74fb,
        0x537be77a8bde735,
        0x0,
        0x400000000000000,
    ]);

    /// `(T - 1) / 2 =`
    /// `904625697166532776746648320380374280107139544922488450750243867285681781373`
    #[rustfmt::skip]
    const T_MINUS_ONE_DIV_TWO: BigInteger256 = BigInt::new([
        0xcb024c634b9eba7d,
        0x29bdf3bd45ef39a,
        0x0,
        0x200000000000000,
    ]);
}

#[cfg(test)]
mod test {
    use crate::curve::curve25519::fr::Fr;
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
