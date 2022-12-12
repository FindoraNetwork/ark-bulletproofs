use ark_ff::{
    biginteger::{BigInt, BigInteger256},
    fields::{Fp256, Fp256Parameters, FpParameters},
    FftParameters,
};

pub type Fq = Fp256<FqParameters>;

pub struct FqParameters;

impl Fp256Parameters for FqParameters {}

impl FftParameters for FqParameters {
    type BigInt = BigInteger256;
    const TWO_ADICITY: u32 = 5;

    #[rustfmt::skip]
    const TWO_ADIC_ROOT_OF_UNITY: Self::BigInt = BigInt::new([
        0x87afabe7de24fcef,
        0x698a623788a2a5a7,
        0x8d04d096279b02a3,
        0x63ef83e13fa57227,
    ]);
}

impl FpParameters for FqParameters {
    /// MODULUS = 0x8000000000000000000000000000000169f40306a6210bed885f1923d3651021
    ///         = 57896044618658097711785492504343953927116110621106131396339151912985063395361
    #[rustfmt::skip]
    const MODULUS: BigInteger256 = BigInt::new([
        0x885f1923d3651021,
        0x69f40306a6210bed,
        0x1,
        0x8000000000000000,
    ]);

    const MODULUS_BITS: u32 = 256;

    const CAPACITY: u32 = Self::MODULUS_BITS - 1;

    const REPR_SHAVE_BITS: u32 = 0;

    /// Let `M` be the power of 2^64 nearest to `Self::MODULUS_BITS`. Then
    /// `R = M % Self::MODULUS`.
    ///
    /// `M = 2^{256}`.
    /// `R = 57896044618658097711785492504343953926153874044534432643118432094928066244575`.
    #[rustfmt::skip]
    const R: BigInteger256 = BigInt::new([
        0x77a0e6dc2c9aefdf,
        0x960bfcf959def412,
        0xfffffffffffffffe,
        0x7fffffffffffffff,
    ]);

    /// `R2 = R^2 % Self::MODULUS`.
    /// `R2 = 57458560012551212255205896833982012061272584296340294270170350398946069487381`.
    #[rustfmt::skip]
    const R2: BigInteger256 = BigInt::new([
        0x9c7f4ef214c9f15,
        0xc3e36ed766cc4346,
        0x8c2ca8fed8c31ff6,
        0x7f08647a14fc2ace,
    ]);

    /// `INV = -MODULUS^{-1} mod 2^64`.
    /// `INV = 7804074019544730655`.
    const INV: u64 = 0x6c4da3f917d18c1f;

    /// GENERATOR = 2
    /// Encoded in Montgomery form, so the value here is
    /// `2 * R % q = 57896044618658097711785492504343953924229400891391035136676992458814071943003`
    #[rustfmt::skip]
    const GENERATOR: BigInteger256 = BigInt::new([
        0x5624824cdf06af5b,
        0xee3bf0dec15ac45c,
        0xfffffffffffffff8,
        0x7fffffffffffffff,
    ]);

    #[rustfmt::skip]
    /// `28948022309329048855892746252171976963558055310553065698169575956492531697680`
    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger256 = BigInt::new([
        0xc42f8c91e9b28810,
        0xb4fa0183531085f6,
        0x0,
        0x4000000000000000,
    ]);

    /// T and T_MINUS_ONE_DIV_TWO, where `MODULUS - 1 = 2^S * T`
    /// For T coprime to 2
    ///
    /// In our case, `S = 1`.
    ///
    /// `T = (MODULUS - 1) / 2^S =`
    /// `1809251394333065553493296640760748560222378456909566606135598497280783231105`
    #[rustfmt::skip]
    const T: BigInteger256 = BigInt::new([
        0x6c42f8c91e9b2881,
        0xb4fa0183531085f,
        0x0,
        0x400000000000000,
    ]);

    /// `(T - 1) / 2 =`
    /// `904625697166532776746648320380374280111189228454783303067799248640391615552`
    #[rustfmt::skip]
    const T_MINUS_ONE_DIV_TWO: BigInteger256 = BigInt::new([
        0xb6217c648f4d9440,
        0x5a7d00c1a98842f,
        0x0,
        0x200000000000000,
    ]);
}

#[cfg(test)]
mod test {
    use crate::curve::zorro::fq::Fq;
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
