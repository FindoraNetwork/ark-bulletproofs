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
        0x3b5807d4fe2bdb04,
        0x3f590fdb51be9ed,
        0x6d6e16bf336202d1,
        0x75776b0bd6c71ba8,
    ]);
}

impl FpParameters for FrParameters {
    /// MODULUS = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
    ///         = 57896044618658097711785492504343953926634992332820282019728792003956564819949
    #[rustfmt::skip]
    const MODULUS: BigInteger256 = BigInt::new([
        0xffffffffffffffed,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0x7fffffffffffffff,
    ]);

    const MODULUS_BITS: u32 = 255;

    const CAPACITY: u32 = Self::MODULUS_BITS - 1;

    const REPR_SHAVE_BITS: u32 = 0;

    /// Let `M` be the power of 2^64 nearest to `Self::MODULUS_BITS`. Then
    /// `R = M % Self::MODULUS`.
    ///
    /// `M = 2^{256}`.
    /// `R = 38`.
    #[rustfmt::skip]
    const R: BigInteger256 = BigInt::new([
        0x26,
        0x0,
        0x0,
        0x0,
    ]);

    /// `R2 = R^2 % Self::MODULUS`.
    /// `R2 = 1444`.
    #[rustfmt::skip]
    const R2: BigInteger256 = BigInt::new([
        0x5a4,
        0x0,
        0x0,
        0x0
    ]);

    /// `INV = -MODULUS^{-1} mod 2^64`.
    /// `INV = 9708812670373448219`.
    const INV: u64 = 0x86bca1af286bca1b;

    /// GENERATOR = 2
    /// Encoded in Montgomery form, so the value here is
    /// `2 * R % q = 76`
    #[rustfmt::skip]
    const GENERATOR: BigInteger256 = BigInt::new([
        0x4c,
        0x0,
        0x0,
        0x0,
    ]);

    #[rustfmt::skip]
    /// `28948022309329048855892746252171976963317496166410141009864396001978282409974`
    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger256 = BigInt::new([
        0xfffffffffffffff6,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0x3fffffffffffffff,
    ]);

    /// T and T_MINUS_ONE_DIV_TWO, where `MODULUS - 1 = 2^S * T`
    /// For T coprime to 2
    ///
    /// In our case, `S = 2`.
    ///
    /// `T = (MODULUS - 1) / 2^S =`
    /// `14474011154664524427946373126085988481658748083205070504932198000989141204987`
    #[rustfmt::skip]
    const T: BigInteger256 = BigInt::new([
        0xfffffffffffffffb,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0x1fffffffffffffff,
    ]);

    /// `(T - 1) / 2 =`
    /// `7237005577332262213973186563042994240829374041602535252466099000494570602493`
    #[rustfmt::skip]
    const T_MINUS_ONE_DIV_TWO: BigInteger256 = BigInt::new([
        0xfffffffffffffffd,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xfffffffffffffff,
    ]);
}

#[cfg(test)]
mod test {
    use crate::curve::zorro::fr::Fr;
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






