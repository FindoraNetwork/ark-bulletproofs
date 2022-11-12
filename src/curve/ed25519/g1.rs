use ark_ec::{
    twisted_edwards_extended::{GroupAffine, GroupProjective},
    ModelParameters, MontgomeryModelParameters, TEModelParameters,
};
use ark_ff::field_new;

use crate::curve::ed25519::{Fq, Fr};

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Parameters;

pub type G1Affine = GroupAffine<Parameters>;
pub type G1Projective = GroupProjective<Parameters>;

impl ModelParameters for Parameters {
    type BaseField = Fq;
    type ScalarField = Fr;

    /// COFACTOR = 8
    const COFACTOR: &'static [u64] = &[0x8];

    /// COFACTOR_INV = COFACTOR^{-1} mod r = 2713877091499598330239944961141122840321418634767465352250731601857045344121
    #[rustfmt::skip]
    const COFACTOR_INV: Fr = field_new!(Fr, "2713877091499598330239944961141122840321418634767465352250731601857045344121");
}

impl TEModelParameters for Parameters {
    /// COEFF_A = -1
    const COEFF_A: Fq = field_new!(Fq, "-1");

    /// COEFF_D = -121665 / 121666
    const COEFF_D: Fq = field_new!(Fq, "37095705934669439343138083508754565189542113879843219016388785533085940283555");

    /// AFFINE_GENERATOR_COEFFS = (G1_GENERATOR_X, G1_GENERATOR_Y)
    const AFFINE_GENERATOR_COEFFS: (Self::BaseField, Self::BaseField) =
        (G1_GENERATOR_X, G1_GENERATOR_Y);

    type MontgomeryModelParameters = Parameters;
}

/// G1_GENERATOR_X = 15112221349535400772501151409588531511454012693041857206046113283949847762202
pub const G1_GENERATOR_X: Fq = field_new!(
    Fq,
    "15112221349535400772501151409588531511454012693041857206046113283949847762202"
);

/// G1_GENERATOR_Y = 4/5
///                = 46316835694926478169428394003475163141307993866256225615783033603165251855960
pub const G1_GENERATOR_Y: Fq = field_new!(
    Fq,
    "46316835694926478169428394003475163141307993866256225615783033603165251855960"
);

impl MontgomeryModelParameters for Parameters {
    /// COEFF_A = 486662
    const COEFF_A: Fq = field_new!(Fq, "486662");

    /// COEFF_B = 57896044618658097711785492504343953926634992332820282019728792003956564333285
    const COEFF_B: Fq = field_new!(Fq, "57896044618658097711785492504343953926634992332820282019728792003956564333285");

    type TEModelParameters = Parameters;
}

#[cfg(test)]
mod test {
    use crate::curve::ed25519::g1::{G1Affine, G1Projective, Parameters};
    use ark_algebra_test_templates::{
        curves::{curve_tests, edwards_curve_serialization_test, montgomery_conversion_test},
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
    fn test_edwards_curve_serialization() {
        edwards_curve_serialization_test::<Parameters>();
    }

    #[test]
    fn test_montgomery_conversion() {
        montgomery_conversion_test::<Parameters>();
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
