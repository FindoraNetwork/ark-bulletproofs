//! The `messages` module contains the API for the messages passed between the parties and the dealer
//! in an aggregated multiparty computation protocol.
//!
//! For more explanation of how the `dealer`, `party`, and `messages` modules orchestrate the protocol execution, see
//! [the API for the aggregated multiparty computation protocol](../aggregation/index.html#api-for-the-aggregated-multiparty-computation-protocol).

use ark_ec::msm;
use ark_ff::{Field, PrimeField};
use ark_std::{iter, ops::Neg, vec::Vec, One, Zero};

use crate::curve::bs257::{BigIntType, Fr, G1Affine};
use crate::generators::{BulletproofGens, PedersenGens};

/// A commitment to the bits of a party's value.
#[derive(Copy, Clone, Debug)]
pub struct BitCommitment {
    pub(super) V_j: G1Affine,
    pub(super) A_j: G1Affine,
    pub(super) S_j: G1Affine,
}

/// Challenge values derived from all parties' [`BitCommitment`]s.
#[derive(Copy, Clone, Debug)]
pub struct BitChallenge {
    pub(super) y: Fr,
    pub(super) z: Fr,
}

/// A commitment to a party's polynomial coefficents.
#[derive(Copy, Clone, Debug)]
pub struct PolyCommitment {
    pub(super) T_1_j: G1Affine,
    pub(super) T_2_j: G1Affine,
}

/// Challenge values derived from all parties' [`PolyCommitment`]s.
#[derive(Copy, Clone, Debug)]
pub struct PolyChallenge {
    pub(super) x: Fr,
}

/// A party's proof share, ready for aggregation into the final
/// [`RangeProof`](::RangeProof).
#[derive(Clone, Debug)]
pub struct ProofShare {
    pub(super) t_x: Fr,
    pub(super) t_x_blinding: Fr,
    pub(super) e_blinding: Fr,
    pub(super) l_vec: Vec<Fr>,
    pub(super) r_vec: Vec<Fr>,
}

impl ProofShare {
    /// Checks consistency of all sizes in the proof share and returns the size of the l/r vector.
    pub(super) fn check_size(
        &self,
        expected_n: usize,
        bp_gens: &BulletproofGens,
        j: usize,
    ) -> Result<(), ()> {
        if self.l_vec.len() != expected_n {
            return Err(());
        }

        if self.r_vec.len() != expected_n {
            return Err(());
        }

        if expected_n > bp_gens.gens_capacity {
            return Err(());
        }

        if j >= bp_gens.party_capacity {
            return Err(());
        }

        Ok(())
    }

    /// Audit an individual proof share to determine whether it is
    /// malformed.
    pub(super) fn audit_share(
        &self,
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        j: usize,
        bit_commitment: &BitCommitment,
        bit_challenge: &BitChallenge,
        poly_commitment: &PolyCommitment,
        poly_challenge: &PolyChallenge,
    ) -> Result<(), ()> {
        use crate::inner_product_proof::inner_product;
        use crate::util;

        let n = self.l_vec.len();

        self.check_size(n, bp_gens, j)?;

        let (y, z) = (&bit_challenge.y, &bit_challenge.z);
        let x = &poly_challenge.x;

        // Precompute some variables
        let zz = *z * z;
        let minus_z = z.neg();
        let z_j = z.pow(&[j as u64]); // z^j
        let y_jn = y.pow(&[(j * n) as u64]); // y^(j*n)
        let y_jn_inv = y_jn.inverse().unwrap(); // y^(-j*n)
        let y_inv = y.inverse().unwrap(); // y^(-1)

        if self.t_x != inner_product(&self.l_vec, &self.r_vec) {
            return Err(());
        }

        let g = self.l_vec.iter().map(|l_i| minus_z - l_i);
        let h = self
            .r_vec
            .iter()
            .zip(util::exp_iter(Fr::from(2u64)))
            .zip(util::exp_iter(y_inv))
            .map(|((r_i, exp_2), exp_y_inv)| {
                *z + exp_y_inv * y_jn_inv * r_i.neg() + exp_y_inv * y_jn_inv * (zz * z_j * exp_2)
            });

        let P_check = msm::VariableBase::msm(
            &iter::once(&bit_commitment.A_j)
                .chain(iter::once(&bit_commitment.S_j))
                .chain(iter::once(&pc_gens.B_blinding))
                .chain(bp_gens.share(j).G(n))
                .chain(bp_gens.share(j).H(n))
                .map(|f| f.clone())
                .collect::<Vec<G1Affine>>(),
            &iter::once(Fr::one())
                .chain(iter::once(*x))
                .chain(iter::once(self.e_blinding.neg()))
                .chain(g)
                .chain(h)
                .map(|f| f.into_repr())
                .collect::<Vec<BigIntType>>(),
        );
        if !P_check.is_zero() {
            return Err(());
        }

        let sum_of_powers_y = util::sum_of_powers(&y, n);
        let sum_of_powers_2 = util::sum_of_powers(&Fr::from(2u64), n);
        let delta = (*z - zz) * sum_of_powers_y * y_jn - *z * zz * sum_of_powers_2 * z_j;
        let t_check = msm::VariableBase::msm(
            &iter::once(&bit_commitment.V_j)
                .chain(iter::once(&poly_commitment.T_1_j))
                .chain(iter::once(&poly_commitment.T_2_j))
                .chain(iter::once(&pc_gens.B))
                .chain(iter::once(&pc_gens.B_blinding))
                .map(|f| f.clone())
                .collect::<Vec<G1Affine>>(),
            &iter::once(zz * z_j)
                .chain(iter::once(*x))
                .chain(iter::once(*x * x))
                .chain(iter::once(delta - &self.t_x))
                .chain(iter::once(self.t_x_blinding.neg()))
                .map(|f| f.into_repr())
                .collect::<Vec<BigIntType>>(),
        );

        if t_check.is_zero() {
            Ok(())
        } else {
            Err(())
        }
    }
}
