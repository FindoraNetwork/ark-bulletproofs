use ark_ff::{
    biginteger::{BigInt, BigInteger320},
    fields::{Fp320, Fp320Parameters, FpParameters},
    FftParameters,
};

pub type Fq = Fp320<FqParameters>;

pub struct FqParameters;

impl Fp320Parameters for FqParameters {}

impl FftParameters for FqParameters {
    type BigInt = BigInteger320;
    const TWO_ADICITY: u32 = 5;
    const TWO_ADIC_ROOT_OF_UNITY: Self::BigInt = BigInt::new([
        0x717a2e0ee59a4753,
        0xde10faf65209112d,
        0x10af959a36aaede3,
        0xdeed3dfd517127a6,
        0x0,
    ]);
}

impl FpParameters for FqParameters {
    /// MODULUS = 0x1000000000000000000000000000000011225471b50b8dc249e5ff726d4163f21
    ///         = 115792089237316195423570985008687907853634386693684621307141857813043191627553
    #[rustfmt::skip]
    const MODULUS: BigInteger320 = BigInt::new([
        0x9e5ff726d4163f21,
        0x1225471b50b8dc24,
        0x1,
        0x0,
        0x1,
    ]);

    const MODULUS_BITS: u32 = 257;

    const CAPACITY: u32 = Self::MODULUS_BITS - 1;

    const REPR_SHAVE_BITS: u32 = 63;

    /// Let `M` be the power of 2^64 nearest to `Self::MODULUS_BITS`. Then
    /// `R = M % Self::MODULUS`.
    ///
    /// `M = 2^{320}`.
    /// `R = 115792089237316195416848954057418452620234596290110572286728859095508377288481`.
    #[rustfmt::skip]
    const R: BigInteger320 = BigInt::new([
        0x9e5ff726d4163f21,
        0x73c54ff47ca29d03,
        0xeddab8e4af4723dc,
        0xfffffffffffffffe,
        0x0,
    ]);

    /// `R2 = R^2 % Self::MODULUS`.
    /// `R2 = 17637168485989770643912989497113284166853135771825827723165605189791855617662`.
    #[rustfmt::skip]
    const R2: BigInteger320 = BigInt::new([
        0x0618128ae993267e,
        0x65320f396a714a82,
        0xc995acd78b45c22e,
        0x26fe489a4a187c74,
        0x0,
    ]);

    /// `INV = -MODULUS^{-1} mod 2^64`.
    /// `INV = 11857564640349911839`.
    const INV: u64 = 0xa48e88376149fb1f;

    /// GENERATOR = 5
    /// Encoded in Montgomery form, so the value here is
    /// `5 * R % q = 115792089237316195389960830252340631686635434675814376205076864225369119932193`
    #[rustfmt::skip]
    const GENERATOR: BigInteger320 = BigInt::new([
        0x9e5ff726d4163f21,
        0xfa4573592c49a07f,
        0xa5459c776c63b349,
        0xfffffffffffffffa,
        0x0,
    ]);

    #[rustfmt::skip]
    /// `57896044618658097711785492504343953926817193346842310653570928906521595813776`
    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger320 = BigInt::new([
        0x4f2ffb936a0b1f90,
        0x8912a38da85c6e12,
        0x0,
        0x8000000000000000,
        0x0
    ]);

    /// T and T_MINUS_ONE_DIV_TWO, where `MODULUS - 1 = 2^S * T`
    /// For T coprime to 2
    ///
    /// In our case, `S = 5`.
    ///
    /// `T = (MODULUS - 1) / 2^S =`
    /// `3618502788666131106986593281521497120426074584177644415848183056657599738361`
    ///
    #[rustfmt::skip]
    const T: BigInteger320 = BigInt::new([
        0x24f2ffb936a0b1f9,
        0x08912a38da85c6e1,
        0x0,
        0x0800000000000000,
        0x0,
    ]);

    /// `(T - 1) / 2 =`
    /// `1809251394333065553493296640760748560213037292088822207924091528328799869180`
    #[rustfmt::skip]
    const T_MINUS_ONE_DIV_TWO: BigInteger320 = BigInt::new([
        0x92797fdc9b5058fc,
        0x0448951c6d42e370,
        0x0,
        0x0400000000000000,
        0x0
    ]);
}

#[cfg(test)]
mod test {
    use crate::curve::canaan::fq::Fq;
    use ark_algebra_test_templates::fields::{field_test, primefield_test};
    use ark_ff::{Field, One, UniformRand, Zero};
    use ark_std::{
        ops::{AddAssign, MulAssign, SubAssign},
        test_rng,
    };

    pub(crate) const ITERATIONS: usize = 5;

    #[test]
    fn test_fq() {
        let mut rng = ark_std::test_rng();
        for _ in 0..ITERATIONS {
            let a: Fq = UniformRand::rand(&mut rng);
            let b: Fq = UniformRand::rand(&mut rng);
            field_test(a, b);
            primefield_test::<Fq>();
        }
    }

    #[test]
    fn test_fq_add_assign() {
        // Test associativity

        let mut rng = test_rng();

        for _ in 0..1000 {
            // Generate a, b, c and ensure (a + b) + c == a + (b + c).
            let a = Fq::rand(&mut rng);
            let b = Fq::rand(&mut rng);
            let c = Fq::rand(&mut rng);

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
    fn test_fq_sub_assign() {
        let mut rng = test_rng();

        for _ in 0..1000 {
            // Ensure that (a - b) + (b - a) = 0.
            let a = Fq::rand(&mut rng);
            let b = Fq::rand(&mut rng);

            let mut tmp1 = a;
            tmp1.sub_assign(&b);

            let mut tmp2 = b;
            tmp2.sub_assign(&a);

            tmp1.add_assign(&tmp2);
            assert!(tmp1.is_zero());
        }
    }

    #[test]
    fn test_fq_mul_assign() {
        let mut rng = test_rng();

        for _ in 0..1000 {
            // Ensure that (a * b) * c = a * (b * c)
            let a = Fq::rand(&mut rng);
            let b = Fq::rand(&mut rng);
            let c = Fq::rand(&mut rng);

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

            let r = Fq::rand(&mut rng);
            let mut a = Fq::rand(&mut rng);
            let mut b = Fq::rand(&mut rng);
            let mut c = Fq::rand(&mut rng);

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
    fn test_fq_squaring() {
        let mut rng = test_rng();

        for _ in 0..1000 {
            // Ensure that (a * a) = a^2
            let a = Fq::rand(&mut rng);

            let mut tmp = a;
            tmp.square_in_place();

            let mut tmp2 = a;
            tmp2.mul_assign(&a);

            assert_eq!(tmp, tmp2);
        }
    }

    #[test]
    fn test_fq_inverse() {
        assert!(Fq::zero().inverse().is_none());

        let mut rng = test_rng();

        let one = Fq::one();

        for _ in 0..1000 {
            // Ensure that a * a^-1 = 1
            let mut a = Fq::rand(&mut rng);
            let ainv = a.inverse().unwrap();
            a.mul_assign(&ainv);
            assert_eq!(a, one);
        }
    }

    #[test]
    fn test_fq_double_in_place() {
        let mut rng = test_rng();

        for _ in 0..1000 {
            // Ensure doubling a is equivalent to adding a to itself.
            let mut a = Fq::rand(&mut rng);
            let mut b = a;
            b.add_assign(&a);
            a.double_in_place();
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_fq_negate() {
        {
            let a = -Fq::zero();

            assert!(a.is_zero());
        }

        let mut rng = test_rng();

        for _ in 0..1000 {
            // Ensure (a - (-a)) = 0.
            let mut a = Fq::rand(&mut rng);
            let b = -a;
            a.add_assign(&b);

            assert!(a.is_zero());
        }
    }

    #[test]
    fn test_fq_pow() {
        let mut rng = test_rng();

        for i in 0..1000 {
            // Exponentiate by various small numbers and ensure it consists with repeated
            // multiplication.
            let a = Fq::rand(&mut rng);
            let target = a.pow(&[i]);
            let mut c = Fq::one();
            for _ in 0..i {
                c.mul_assign(&a);
            }
            assert_eq!(c, target);
        }

        for _ in 0..1000 {
            // Exponentiating by the modulus should have no effect in a prime field.
            let a = Fq::rand(&mut rng);

            assert_eq!(a, a.pow(Fq::characteristic()));
        }
    }
}
