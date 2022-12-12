use core::ops::Mul;

use crate::curve::zorro::{Fq, Fr};
use ark_ec::{
    short_weierstrass_jacobian::{GroupAffine, GroupProjective},
    ModelParameters, SWModelParameters,
};
use ark_ff::field_new;

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Parameters;

pub type G1Affine = GroupAffine<Parameters>;
pub type G1Projective = GroupProjective<Parameters>;

impl ModelParameters for Parameters {
    type BaseField = Fq;
    type ScalarField = Fr;

    /// COFACTOR = 2
    const COFACTOR: &'static [u64] = &[0x1];

    /// COFACTOR_INV = COFACTOR^{-1} mod r = 1
    #[rustfmt::skip]
    const COFACTOR_INV: Fr = field_new!(Fr, "1");
}

impl SWModelParameters for Parameters {
    /// COEFF_A = 6
    const COEFF_A: Fq = field_new!(Fq, "6");

    /// COEFF_B = 7277470329389939148381533754641607518092114590371880995609984561067837624798
    const COEFF_B: Fq = field_new!(
        Fq,
        "7277470329389939148381533754641607518092114590371880995609984561067837624798"
    );

    /// AFFINE_GENERATOR_COEFFS = (G1_GENERATOR_X, G1_GENERATOR_Y)
    const AFFINE_GENERATOR_COEFFS: (Self::BaseField, Self::BaseField) =
        (G1_GENERATOR_X, G1_GENERATOR_Y);

    #[inline(always)]
    fn mul_by_a(x: &Self::BaseField) -> Self::BaseField {
        x.mul(Self::COEFF_A)
    }
}

/// G1_GENERATOR_X = 2
pub const G1_GENERATOR_X: Fq = field_new!(Fq, "2");

/// G1_GENERATOR_Y = 19711758720854384559191066596451394956860102304684364148268676039962145446511
pub const G1_GENERATOR_Y: Fq = field_new!(
    Fq,
    "19711758720854384559191066596451394956860102304684364148268676039962145446511"
);

#[cfg(test)]
mod test {
    use crate::curve::zorro::g1::{G1Affine, G1Projective, Parameters};
    use ark_algebra_test_templates::{
        curves::{curve_tests, sw_tests},
        groups::group_test,
        msm::test_var_base_msm,
    };
    use ark_ec::AffineCurve;
    use ark_std::rand::Rng;

    #[test]
    fn test_g1_projective_curve() {
        curve_tests::<G1Projective>();
    }

    #[test]
    fn test_g1_projective_sw() {
        sw_tests::<Parameters>();
    }

    #[test]
    fn test_g1_affine_curve() {
        test_var_base_msm::<G1Affine>();
        ark_algebra_test_templates::msm::test_chunked_pippenger::<G1Affine>();
    }

    #[test]
    fn test_g1_projective_group() {
        let mut rng = ark_std::test_rng();
        let a: G1Projective = rng.gen();
        let b: G1Projective = rng.gen();
        group_test(a, b);
    }

    #[test]
    fn test_g1_generator() {
        let generator = G1Affine::prime_subgroup_generator();
        assert!(generator.is_on_curve());
    }
}
