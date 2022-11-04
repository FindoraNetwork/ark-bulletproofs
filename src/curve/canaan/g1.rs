use crate::curve::canaan::{Fq, Fr};
use ark_ec::{
    short_weierstrass_jacobian::{GroupAffine, GroupProjective},
    ModelParameters, SWModelParameters,
};
use ark_ff::field_new;
use ark_std::ops::Mul;

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Parameters;

pub type G1Affine = GroupAffine<Parameters>;
pub type G1Projective = GroupProjective<Parameters>;

impl ModelParameters for Parameters {
    type BaseField = Fq;
    type ScalarField = Fr;

    /// COFACTOR = 1
    const COFACTOR: &'static [u64] = &[0x1];

    /// COFACTOR_INV = COFACTOR^{-1} mod r = 1
    #[rustfmt::skip]
    const COFACTOR_INV: Fr = field_new!(Fr, "1");
}

impl SWModelParameters for Parameters {
    /// COEFF_A = 5535550953020464033774697179068783537293233400326936244723618588471535946749
    const COEFF_A: Fq = field_new!(
        Fq,
        "5535550953020464033774697179068783537293233400326936244723618588471535946749"
    );

    /// COEFF_B = 36647759370566527599092766378540222398030651415577287046115147687263277949759
    const COEFF_B: Fq = field_new!(
        Fq,
        "36647759370566527599092766378540222398030651415577287046115147687263277949759"
    );

    /// AFFINE_GENERATOR_COEFFS = (G1_GENERATOR_X, G1_GENERATOR_Y)
    const AFFINE_GENERATOR_COEFFS: (Self::BaseField, Self::BaseField) =
        (G1_GENERATOR_X, G1_GENERATOR_Y);

    #[inline(always)]
    fn mul_by_a(x: &Self::BaseField) -> Self::BaseField {
        x.mul(Self::COEFF_A)
    }
}

/// G1_GENERATOR_X = 112705626237469359431210032935145282355350935647148544791154076438707398138640
pub const G1_GENERATOR_X: Fq = field_new!(
    Fq,
    "112705626237469359431210032935145282355350935647148544791154076438707398138640"
);

/// G1_GENERATOR_Y = 89549966215394383044207691912783583524034482147603090211899998092343754082310
pub const G1_GENERATOR_Y: Fq = field_new!(
    Fq,
    "89549966215394383044207691912783583524034482147603090211899998092343754082310"
);

#[cfg(test)]
mod test {
    use crate::curve::canaan::g1::{G1Affine, G1Projective, Parameters};
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
