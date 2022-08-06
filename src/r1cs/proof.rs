#![allow(non_snake_case)]
//! Definition of the proof struct.

use crate::{
    curve::secq256k1::{Fr, G1Affine},
    errors::R1CSError,
    inner_product_proof::InnerProductProof,
    ProofError,
};
use ark_ff::{FromBytes, ToBytes};
use ark_std::{
    io::{Cursor, Read, Write},
    Zero,
};

const ONE_PHASE_COMMITMENTS: u8 = 0;
const TWO_PHASE_COMMITMENTS: u8 = 1;

/// A proof of some statement specified by a
/// [`ConstraintSystem`](::r1cs::ConstraintSystem).
///
/// Statements are specified by writing gadget functions which add
/// constraints to a [`ConstraintSystem`](::r1cs::ConstraintSystem)
/// implementation.  To construct an [`R1CSProof`], a prover constructs
/// a [`ProverCS`](::r1cs::ProverCS), then passes it to gadget
/// functions to build the constraint system, then consumes the
/// constraint system using
/// [`ProverCS::prove`](::r1cs::ProverCS::prove) to produce an
/// [`R1CSProof`].  To verify an [`R1CSProof`], a verifier constructs a
/// [`VerifierCS`](::r1cs::VerifierCS), then passes it to the same
/// gadget functions to (re)build the constraint system, then consumes
/// the constraint system using
/// [`VerifierCS::verify`](::r1cs::VerifierCS::verify) to verify the
/// proof.
#[derive(Clone, Debug)]
#[allow(non_snake_case)]
pub struct R1CSProof {
    /// Commitment to the values of input wires in the first phase.
    pub(super) A_I1: G1Affine,
    /// Commitment to the values of output wires in the first phase.
    pub(super) A_O1: G1Affine,
    /// Commitment to the blinding factors in the first phase.
    pub(super) S1: G1Affine,
    /// Commitment to the values of input wires in the second phase.
    pub(super) A_I2: G1Affine,
    /// Commitment to the values of output wires in the second phase.
    pub(super) A_O2: G1Affine,
    /// Commitment to the blinding factors in the second phase.
    pub(super) S2: G1Affine,
    /// Commitment to the \\(t_1\\) coefficient of \\( t(x) \\)
    pub(super) T_1: G1Affine,
    /// Commitment to the \\(t_3\\) coefficient of \\( t(x) \\)
    pub(super) T_3: G1Affine,
    /// Commitment to the \\(t_4\\) coefficient of \\( t(x) \\)
    pub(super) T_4: G1Affine,
    /// Commitment to the \\(t_5\\) coefficient of \\( t(x) \\)
    pub(super) T_5: G1Affine,
    /// Commitment to the \\(t_6\\) coefficient of \\( t(x) \\)
    pub(super) T_6: G1Affine,
    /// Evaluation of the polynomial \\(t(x)\\) at the challenge point \\(x\\)
    pub(super) t_x: Fr,
    /// Blinding factor for the synthetic commitment to \\( t(x) \\)
    pub(super) t_x_blinding: Fr,
    /// Blinding factor for the synthetic commitment to the
    /// inner-product arguments
    pub(super) e_blinding: Fr,
    /// Proof data for the inner-product argument.
    pub(super) ipp_proof: InnerProductProof,
}

impl R1CSProof {
    /// Serializes the proof into a byte array of 1 version byte + \\((13 or 16) + 2k\\) 32-byte elements,
    /// where \\(k=\lceil \log_2(n) \rceil\\) and \\(n\\) is the number of multiplication gates.
    ///
    /// # Layout
    ///
    /// The layout of the r1cs proof encoding is:
    /// * 1 version byte indicating whether the proof contains second-phase commitments or not,
    /// * 8 or 11 compressed Ristretto points \\(A_{I1},A_{O1},S_1,(A_{I2},A_{O2},S_2),T_1,...,T_6\\)
    ///   (\\(A_{I2},A_{O2},S_2\\) are skipped if there were no multipliers added in the randomized phase),
    /// * three scalars \\(t_x, \tilde{t}_x, \tilde{e}\\),
    /// * \\(k\\) pairs of compressed Ristretto points \\(L_0,R_0\dots,L_{k-1},R_{k-1}\\),
    /// * two scalars \\(a, b\\).
    pub fn to_bytes(&self) -> Result<Vec<u8>, ProofError> {
        let mut cursor = Cursor::new(Vec::new());
        self.write(&mut cursor)?;
        Ok(cursor.into_inner())
    }

    /// Returns the size in bytes required to serialize the `R1CSProof`.
    pub fn serialized_size(&self) -> usize {
        // version tag + (11 or 14) elements + the ipp
        let elements = if self.missing_phase2_commitments() {
            11
        } else {
            14
        };
        1 + elements * 32 + self.ipp_proof.serialized_size()
    }

    fn missing_phase2_commitments(&self) -> bool {
        self.A_I2.is_zero() && self.A_O2.is_zero() && self.S2.is_zero()
    }

    /// Deserializes the proof from a byte slice.
    ///
    /// Returns an error if the byte slice cannot be parsed into a `R1CSProof`.
    pub fn from_bytes(slice: &[u8]) -> Result<R1CSProof, R1CSError> {
        let mut cursor = Cursor::new(slice);
        let proof = R1CSProof::read(&mut cursor);
        if proof.is_ok() {
            Ok(proof.unwrap())
        } else {
            Err(R1CSError::FormatError)
        }
    }
}

impl ToBytes for R1CSProof {
    fn write<W: Write>(&self, mut writer: W) -> ark_std::io::Result<()> {
        if self.missing_phase2_commitments() {
            ONE_PHASE_COMMITMENTS.write(&mut writer)?;
            self.A_I1.write(&mut writer)?;
            self.A_O1.write(&mut writer)?;
            self.S1.write(&mut writer)?;
        } else {
            TWO_PHASE_COMMITMENTS.write(&mut writer)?;
            self.A_I1.write(&mut writer)?;
            self.A_O1.write(&mut writer)?;
            self.S1.write(&mut writer)?;
            self.A_I2.write(&mut writer)?;
            self.A_O2.write(&mut writer)?;
            self.S2.write(&mut writer)?;
        }
        self.T_1.write(&mut writer)?;
        self.T_3.write(&mut writer)?;
        self.T_4.write(&mut writer)?;
        self.T_5.write(&mut writer)?;
        self.T_6.write(&mut writer)?;
        self.t_x.write(&mut writer)?;
        self.t_x_blinding.write(&mut writer)?;
        self.e_blinding.write(&mut writer)?;
        self.ipp_proof.write(&mut writer)
    }
}

impl FromBytes for R1CSProof {
    fn read<R: Read>(mut reader: R) -> ark_std::io::Result<Self> {
        let missing_phases2_commitments = {
            let flag = u8::read(&mut reader)?;
            flag == ONE_PHASE_COMMITMENTS
        };

        if missing_phases2_commitments {
            let A_I1 = G1Affine::read(&mut reader)?;
            let A_O1 = G1Affine::read(&mut reader)?;
            let S1 = G1Affine::read(&mut reader)?;

            let T_1 = G1Affine::read(&mut reader)?;
            let T_3 = G1Affine::read(&mut reader)?;
            let T_4 = G1Affine::read(&mut reader)?;
            let T_5 = G1Affine::read(&mut reader)?;
            let T_6 = G1Affine::read(&mut reader)?;

            let t_x = Fr::read(&mut reader)?;
            let t_x_blinding = Fr::read(&mut reader)?;
            let e_blinding = Fr::read(&mut reader)?;

            let ipp_proof = InnerProductProof::read(&mut reader)?;

            Ok(Self {
                A_I1,
                A_O1,
                S1,
                A_I2: G1Affine::zero(),
                A_O2: G1Affine::zero(),
                S2: G1Affine::zero(),
                T_1,
                T_3,
                T_4,
                T_5,
                T_6,
                t_x,
                t_x_blinding,
                e_blinding,
                ipp_proof,
            })
        } else {
            let A_I1 = G1Affine::read(&mut reader)?;
            let A_O1 = G1Affine::read(&mut reader)?;
            let S1 = G1Affine::read(&mut reader)?;

            let A_I2 = G1Affine::read(&mut reader)?;
            let A_O2 = G1Affine::read(&mut reader)?;
            let S2 = G1Affine::read(&mut reader)?;

            let T_1 = G1Affine::read(&mut reader)?;
            let T_3 = G1Affine::read(&mut reader)?;
            let T_4 = G1Affine::read(&mut reader)?;
            let T_5 = G1Affine::read(&mut reader)?;
            let T_6 = G1Affine::read(&mut reader)?;

            let t_x = Fr::read(&mut reader)?;
            let t_x_blinding = Fr::read(&mut reader)?;
            let e_blinding = Fr::read(&mut reader)?;

            let ipp_proof = InnerProductProof::read(&mut reader)?;

            Ok(Self {
                A_I1,
                A_O1,
                S1,
                A_I2,
                A_O2,
                S2,
                T_1,
                T_3,
                T_4,
                T_5,
                T_6,
                t_x,
                t_x_blinding,
                e_blinding,
                ipp_proof,
            })
        }
    }
}
