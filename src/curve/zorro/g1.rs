use crate::curve::zorro::{Fq, Fr};
use ark_ec::{models::CurveConfig, short_weierstrass::*};
use ark_ff::{Field, MontFp};

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Parameters;

pub type G1Affine = Affine<Parameters>;
pub type G1Projective = Projective<Parameters>;

impl CurveConfig for Parameters {
    type BaseField = Fq;
    type ScalarField = Fr;

    /// COFACTOR = 1
    const COFACTOR: &'static [u64] = &[0x1];

    /// COFACTOR_INV = COFACTOR^{-1} mod r = 1
    #[rustfmt::skip]
    const COFACTOR_INV: Fr = Fr::ONE;
}

impl SWCurveConfig for Parameters {
    /// COEFF_A = 6
    const COEFF_A: Fq = MontFp!("6");

    /// COEFF_B = 7277470329389939148381533754641607518092114590371880995609984561067837624798
    const COEFF_B: Fq =
        MontFp!("7277470329389939148381533754641607518092114590371880995609984561067837624798");

    /// AFFINE_GENERATOR_COEFFS = (G1_GENERATOR_X, G1_GENERATOR_Y)
    const GENERATOR: Affine<Self> = Affine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);

    #[inline(always)]
    fn mul_by_a(x: Self::BaseField) -> Self::BaseField {
        let y = &x + &x + &x;
        y + &y
    }
}

/// G_GENERATOR_X = 2
pub const G_GENERATOR_X: Fq = MontFp!("2");

/// G_GENERATOR_Y = 19711758720854384559191066596451394956860102304684364148268676039962145446511
pub const G_GENERATOR_Y: Fq =
    MontFp!("19711758720854384559191066596451394956860102304684364148268676039962145446511");
