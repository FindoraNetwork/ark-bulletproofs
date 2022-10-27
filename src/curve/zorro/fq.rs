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
    const TWO_ADICITY: u32 = 1;
    const TWO_ADIC_ROOT_OF_UNITY: Self::BigInt = BigInt::new([  
        0x0,
        0x51bf8b26ea50fecb,
        0x36890df020c720aa,
        0x1,
        0x0,
    ]);
}

impl FpParameters for FqParameters {
    /// MODULUS = 0x10000000000000000000000000000000136890df020c720aa51bf8b26ea50fecb
    ///         = 115792089237316195423570985008687907853682756971699735333147980285963064639179
    #[rustfmt::skip]
    const MODULUS: BigInteger320 = BigInt::new([
        0x51bf8b26ea50fecb,
        0x36890df020c720aa,
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
    /// `R = 115792089237316195415956679918099464547703365549502005605056193841816235212491`.
    #[rustfmt::skip]
    const R: BigInteger320 = BigInt::new([
        0x51bf8b26ea50fecb,
        0xe4c982c9367621df,
        0xc976f20fdf38df56,
        0xfffffffffffffffe,
        0x0,
    ]);

    /// `R2 = R^2 % Self::MODULUS`.
    /// `R2 = 87952144448814991120222238096332847185353731516343235297673570405716810602274`.
    #[rustfmt::skip]
    const R2: BigInteger320 = BigInt::new([
        0xe9888ad928dd1722,
        0x480ea40f640555f2,
        0x191fdd0a884fadd3,
        0xc273264f8e930969,
        0x0,
    ]);

    /// `INV = -MODULUS^{-1} mod 2^64`.
    /// `INV = 1856915940073670941`.
    const INV: u64 = 0x19c5173589da091d;

    /// GENERATOR = 2
    /// Encoded in Montgomery form, so the value here is
    /// `2 * R % q = 115792089237316195408342374827511021241723974127304275876964407397669405785803`
    #[rustfmt::skip]
    const GENERATOR: BigInteger320 = BigInt::new([
        0x2,
        0x0,
        0x0,
        0x0,
        0x0,
    ]);

    #[rustfmt::skip]
    /// `57896044618658097711785492504343953926841378485849867666573990142981532319589`
    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger320 = BigInt::new([
        0x28dfc59375287f65,
        0x9b4486f810639055,
        0x0,
        0x8000000000000000,
        0x0,
    ]);

    /// T and T_MINUS_ONE_DIV_TWO, where `MODULUS - 1 = 2^S * T`
    /// For T coprime to 2
    ///
    /// In our case, `S = 1`.
    ///
    /// `T = (MODULUS - 1) / 2^S =`
    /// `57896044618658097711785492504343953926841378485849867666573990142981532319589`
    #[rustfmt::skip]
    const T: BigInteger320 = BigInt::new([
        0x28dfc59375287f65,
        0x9b4486f810639055,
        0x0,
        0x8000000000000000,
        0x0,
    ]);

    /// `(T - 1) / 2 =`
    /// `28948022309329048855892746252171976963420689242924933833286995071490766159794`
    #[rustfmt::skip]
    const T_MINUS_ONE_DIV_TWO: BigInteger320 = BigInt::new([
        0x946fe2c9ba943fb2,
        0x4da2437c0831c82a,
        0x0,
        0x4000000000000000,
        0x0,
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