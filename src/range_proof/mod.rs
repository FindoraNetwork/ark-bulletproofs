#![allow(non_snake_case)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate rand;

#[cfg(feature = "std")]
use self::rand::thread_rng;
use alloc::vec::Vec;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, VartimeMultiscalarMul};
use merlin::Transcript;

use crate::errors::ProofError;
use crate::generators::{BulletproofGens, PedersenGens};
use crate::inner_product_proof::InnerProductProof;
use crate::transcript::TranscriptProtocol;
use crate::util;

use rand_core::{CryptoRng, RngCore};
use serde::de::Visitor;
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};
use std::iter;
use std::ops::AddAssign;

// Modules for MPC protocol

pub mod dealer;
pub mod messages;
pub mod party;

/// The `RangeProof` struct represents a proof that one or more values
/// are in a range.
///
/// The `RangeProof` struct contains functions for creating and
/// verifying aggregated range proofs.  The single-value case is
/// implemented as a special case of aggregated range proofs.
///
/// The bitsize of the range, as well as the list of commitments to
/// the values, are not included in the proof, and must be known to
/// the verifier.
///
/// This implementation requires that both the bitsize `n` and the
/// aggregation size `m` be powers of two, so that `n = 8, 16, 32, 64`
/// and `m = 1, 2, 4, 8, 16, ...`.  Note that the aggregation size is
/// not given as an explicit parameter, but is determined by the
/// number of values or commitments passed to the prover or verifier.
///
/// # Note
///
/// For proving, these functions run the multiparty aggregation
/// protocol locally.  That API is exposed in the [`aggregation`](::range_proof_mpc)
/// module and can be used to perform online aggregation between
/// parties without revealing secret values to each other.
#[derive(Clone, Debug)]
pub struct RangeProof {
    /// Commitment to the bits of the value
    A: CompressedRistretto,
    /// Commitment to the blinding factors
    S: CompressedRistretto,
    /// Commitment to the \\(t_1\\) coefficient of \\( t(x) \\)
    T_1: CompressedRistretto,
    /// Commitment to the \\(t_2\\) coefficient of \\( t(x) \\)
    T_2: CompressedRistretto,
    /// Evaluation of the polynomial \\(t(x)\\) at the challenge point \\(x\\)
    t_x: Scalar,
    /// Blinding factor for the synthetic commitment to \\(t(x)\\)
    t_x_blinding: Scalar,
    /// Blinding factor for the synthetic commitment to the inner-product arguments
    e_blinding: Scalar,
    /// Proof data for the inner-product argument.
    ipp_proof: InnerProductProof,
}

impl RangeProof {
    /// Create a rangeproof for a given pair of value `v` and
    /// blinding scalar `v_blinding`.
    /// This is a convenience wrapper around [`RangeProof::prove_multiple`].
    ///
    /// # Example
    /// ```
    /// extern crate rand;
    /// use rand::thread_rng;
    ///
    /// extern crate curve25519_dalek;
    /// use curve25519_dalek::scalar::Scalar;
    ///
    /// extern crate merlin;
    /// use merlin::Transcript;
    ///
    /// extern crate bulletproofs;
    /// use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
    ///
    /// # fn main() {
    /// // Generators for Pedersen commitments.  These can be selected
    /// // independently of the Bulletproofs generators.
    /// let pc_gens = PedersenGens::default();
    ///
    /// // Generators for Bulletproofs, valid for proofs up to bitsize 64
    /// // and aggregation size up to 1.
    /// let bp_gens = BulletproofGens::new(64, 1);
    ///
    /// // A secret value we want to prove lies in the range [0, 2^32)
    /// let secret_value = 1037578891u64;
    ///
    /// // The API takes a blinding factor for the commitment.
    /// let blinding = Scalar::random(&mut thread_rng());
    ///
    /// // The proof can be chained to an existing transcript.
    /// // Here we create a transcript with a doctest domain separator.
    /// let mut prover_transcript = Transcript::new(b"doctest example");
    ///
    /// // Create a 32-bit rangeproof.
    /// let (proof, committed_value) = RangeProof::prove_single(
    ///     &bp_gens,
    ///     &pc_gens,
    ///     &mut prover_transcript,
    ///     secret_value,
    ///     &blinding,
    ///     32,
    /// ).expect("A real program could handle errors");
    ///
    /// // Verification requires a transcript with identical initial state:
    /// let mut verifier_transcript = Transcript::new(b"doctest example");
    /// assert!(
    ///     proof
    ///         .verify_single(&bp_gens, &pc_gens, &mut verifier_transcript, &committed_value, 32)
    ///         .is_ok()
    /// );
    /// # }
    /// ```
    pub fn prove_single_with_rng<T: RngCore + CryptoRng>(
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        transcript: &mut Transcript,
        v: u64,
        v_blinding: &Scalar,
        n: usize,
        rng: &mut T,
    ) -> Result<(RangeProof, CompressedRistretto), ProofError> {
        let (p, Vs) = RangeProof::prove_multiple_with_rng(
            bp_gens,
            pc_gens,
            transcript,
            &[v],
            &[*v_blinding],
            n,
            rng,
        )?;
        Ok((p, Vs[0]))
    }

    /// Create a rangeproof for a given pair of value `v` and
    /// blinding scalar `v_blinding`.
    /// This is a convenience wrapper around [`RangeProof::prove_single_with_rng`],
    /// passing in a threadsafe RNG.
    #[cfg(feature = "std")]
    pub fn prove_single(
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        transcript: &mut Transcript,
        v: u64,
        v_blinding: &Scalar,
        n: usize,
    ) -> Result<(RangeProof, CompressedRistretto), ProofError> {
        RangeProof::prove_single_with_rng(
            bp_gens,
            pc_gens,
            transcript,
            v,
            v_blinding,
            n,
            &mut thread_rng(),
        )
    }

    /// Create a rangeproof for a set of values.
    ///
    /// # Example
    /// ```
    /// extern crate rand;
    /// use rand::thread_rng;
    ///
    /// extern crate curve25519_dalek;
    /// use curve25519_dalek::scalar::Scalar;
    ///
    /// extern crate merlin;
    /// use merlin::Transcript;
    ///
    /// extern crate bulletproofs;
    /// use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
    ///
    /// # fn main() {
    /// // Generators for Pedersen commitments.  These can be selected
    /// // independently of the Bulletproofs generators.
    /// let pc_gens = PedersenGens::default();
    ///
    /// // Generators for Bulletproofs, valid for proofs up to bitsize 64
    /// // and aggregation size up to 16.
    /// let bp_gens = BulletproofGens::new(64, 16);
    ///
    /// // Four secret values we want to prove lie in the range [0, 2^32)
    /// let secrets = [4242344947u64, 3718732727u64, 2255562556u64, 2526146994u64];
    ///
    /// // The API takes blinding factors for the commitments.
    /// let blindings: Vec<_> = (0..4).map(|_| Scalar::random(&mut thread_rng())).collect();
    ///
    /// // The proof can be chained to an existing transcript.
    /// // Here we create a transcript with a doctest domain separator.
    /// let mut prover_transcript = Transcript::new(b"doctest example");
    ///
    /// // Create an aggregated 32-bit rangeproof and corresponding commitments.
    /// let (proof, commitments) = RangeProof::prove_multiple(
    ///     &bp_gens,
    ///     &pc_gens,
    ///     &mut prover_transcript,
    ///     &secrets,
    ///     &blindings,
    ///     32,
    /// ).expect("A real program could handle errors");
    ///
    /// // Verification requires a transcript with identical initial state:
    /// let mut verifier_transcript = Transcript::new(b"doctest example");
    /// assert!(
    ///     proof
    ///         .verify_multiple(&bp_gens, &pc_gens, &mut verifier_transcript, &commitments, 32)
    ///         .is_ok()
    /// );
    /// # }
    /// ```
    pub fn prove_multiple_with_rng<T: RngCore + CryptoRng>(
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        transcript: &mut Transcript,
        values: &[u64],
        blindings: &[Scalar],
        n: usize,
        rng: &mut T,
    ) -> Result<(RangeProof, Vec<CompressedRistretto>), ProofError> {
        use self::dealer::*;
        use self::party::*;

        if values.len() != blindings.len() {
            return Err(ProofError::WrongNumBlindingFactors);
        }

        let dealer = Dealer::new(bp_gens, pc_gens, transcript, n, values.len())?;

        let parties: Vec<_> = values
            .iter()
            .zip(blindings.iter())
            .map(|(&v, &v_blinding)| Party::new(bp_gens, pc_gens, v, v_blinding, n))
            // Collect the iterator of Results into a Result<Vec>, then unwrap it
            .collect::<Result<Vec<_>, _>>()?;

        let (parties, bit_commitments): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .enumerate()
            .map(|(j, p)| {
                p.assign_position_with_rng(j, rng)
                    .expect("We already checked the parameters, so this should never happen")
            })
            .unzip();

        let value_commitments: Vec<_> = bit_commitments.iter().map(|c| c.V_j).collect();

        let (dealer, bit_challenge) = dealer.receive_bit_commitments(bit_commitments)?;

        let (parties, poly_commitments): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .map(|p| p.apply_challenge_with_rng(&bit_challenge, rng))
            .unzip();

        let (dealer, poly_challenge) = dealer.receive_poly_commitments(poly_commitments)?;

        let proof_shares: Vec<_> = parties
            .into_iter()
            .map(|p| p.apply_challenge(&poly_challenge))
            // Collect the iterator of Results into a Result<Vec>, then unwrap it
            .collect::<Result<Vec<_>, _>>()?;

        let proof = dealer.receive_trusted_shares(&proof_shares)?;

        Ok((proof, value_commitments))
    }

    /// Create a rangeproof for a set of values.
    /// This is a convenience wrapper around [`RangeProof::prove_multiple_with_rng`],
    /// passing in a threadsafe RNG.
    #[cfg(feature = "std")]
    pub fn prove_multiple(
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        transcript: &mut Transcript,
        values: &[u64],
        blindings: &[Scalar],
        n: usize,
    ) -> Result<(RangeProof, Vec<CompressedRistretto>), ProofError> {
        RangeProof::prove_multiple_with_rng(
            bp_gens,
            pc_gens,
            transcript,
            values,
            blindings,
            n,
            &mut thread_rng(),
        )
    }

    /// Verifies a rangeproof for a given value commitment \\(V\\).
    ///
    /// This is a convenience wrapper around `verify_multiple` for the `m=1` case.
    pub fn verify_single_with_rng<T: RngCore + CryptoRng>(
        &self,
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        transcript: &mut Transcript,
        V: &CompressedRistretto,
        n: usize,
        rng: &mut T,
    ) -> Result<(), ProofError> {
        self.verify_multiple_with_rng(bp_gens, pc_gens, transcript, &[*V], n, rng)
    }

    /// Verifies a rangeproof for a given value commitment \\(V\\).
    ///
    /// This is a convenience wrapper around [`RangeProof::verify_single_with_rng`],
    /// passing in a threadsafe RNG.
    #[cfg(feature = "std")]
    pub fn verify_single(
        &self,
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        transcript: &mut Transcript,
        V: &CompressedRistretto,
        n: usize,
    ) -> Result<(), ProofError> {
        self.verify_single_with_rng(bp_gens, pc_gens, transcript, V, n, &mut thread_rng())
    }

    /// Verifies an aggregated rangeproof for the given value commitments.
    pub fn verify_multiple_with_rng<T: RngCore + CryptoRng>(
        &self,
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        transcript: &mut Transcript,
        value_commitments: &[CompressedRistretto],
        n: usize,
        rng: &mut T,
    ) -> Result<(), ProofError> {
        let m = value_commitments.len();

        let scalars = self.compute_verification_scalars_with_rng(
            bp_gens,
            transcript,
            value_commitments,
            n,
            rng,
        )?;

        let mega_check = RistrettoPoint::optional_multiscalar_mul(
            scalars,
            iter::once(self.A.decompress())
                .chain(iter::once(self.S.decompress()))
                .chain(iter::once(self.T_1.decompress()))
                .chain(iter::once(self.T_2.decompress()))
                .chain(self.ipp_proof.L_vec.iter().map(|L| L.decompress()))
                .chain(self.ipp_proof.R_vec.iter().map(|R| R.decompress()))
                .chain(value_commitments.iter().map(|V| V.decompress()))
                .chain(iter::once(Some(pc_gens.B_blinding)))
                .chain(iter::once(Some(pc_gens.B)))
                .chain(bp_gens.G(n, m).map(|&x| Some(x)))
                .chain(bp_gens.H(n, m).map(|&x| Some(x))),
        )
        .ok_or_else(|| ProofError::VerificationError)?;

        if mega_check.is_identity() {
            Ok(())
        } else {
            Err(ProofError::VerificationError)
        }
    }
    /// Compute multiexponentiation scalars needed to verify this proofs
    pub fn compute_verification_scalars_with_rng<T: RngCore + CryptoRng>(
        &self,
        bp_gens: &BulletproofGens,
        transcript: &mut Transcript,
        value_commitments: &[CompressedRistretto],
        n: usize,
        rng: &mut T,
    ) -> Result<Vec<Scalar>, ProofError> {
        let m = value_commitments.len();

        // First, replay the "interactive" protocol using the proof
        // data to recompute all challenges.
        if !(n == 8 || n == 16 || n == 32 || n == 64) {
            return Err(ProofError::InvalidBitsize);
        }
        if bp_gens.gens_capacity < n {
            return Err(ProofError::InvalidGeneratorsLength);
        }
        if bp_gens.party_capacity < m {
            return Err(ProofError::InvalidGeneratorsLength);
        }

        transcript.rangeproof_domain_sep(n as u64, m as u64);

        for V in value_commitments.iter() {
            // Allow the commitments to be zero (0 value, 0 blinding)
            // See https://github.com/dalek-cryptography/bulletproofs/pull/248#discussion_r255167177
            transcript.append_point(b"V", V);
        }

        transcript.validate_and_append_point(b"A", &self.A)?;
        transcript.validate_and_append_point(b"S", &self.S)?;

        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");
        let zz = z * z;
        let minus_z = -z;

        transcript.validate_and_append_point(b"T_1", &self.T_1)?;
        transcript.validate_and_append_point(b"T_2", &self.T_2)?;

        let x = transcript.challenge_scalar(b"x");

        transcript.append_scalar(b"t_x", &self.t_x);
        transcript.append_scalar(b"t_x_blinding", &self.t_x_blinding);
        transcript.append_scalar(b"e_blinding", &self.e_blinding);

        let w = transcript.challenge_scalar(b"w");

        // Challenge value for batching statements to be verified
        let c = Scalar::random(rng);

        let (mut x_sq, mut x_inv_sq, s) = self.ipp_proof.verification_scalars(n * m, transcript)?;
        let s_inv = s.iter().rev();

        let a = self.ipp_proof.a;
        let b = self.ipp_proof.b;

        // Construct concat_z_and_2, an iterator of the values of
        // z^0 * \vec(2)^n || z^1 * \vec(2)^n || ... || z^(m-1) * \vec(2)^n
        let powers_of_2: Vec<Scalar> = util::exp_iter(Scalar::from(2u64)).take(n).collect();
        let concat_z_and_2: Vec<Scalar> = util::exp_iter(z)
            .take(m)
            .flat_map(|exp_z| powers_of_2.iter().map(move |exp_2| exp_2 * exp_z))
            .collect();

        let mut g: Vec<Scalar> = s.iter().map(|s_i| minus_z - a * s_i).collect();
        let mut h: Vec<Scalar> = s_inv
            .zip(util::exp_iter(y.invert()))
            .zip(concat_z_and_2.iter())
            .map(|((s_i_inv, exp_y_inv), z_and_2)| z + exp_y_inv * (zz * z_and_2 - b * s_i_inv))
            .collect();

        let mut value_commitment_scalars: Vec<Scalar> = util::exp_iter(z)
            .take(m)
            .map(|z_exp| c * zz * z_exp)
            .collect();
        let basepoint_scalar = w * (self.t_x - a * b) + c * (delta(n, m, &y, &z) - self.t_x);

        let mut scalars = vec![
            Scalar::one(), // A
            x,             // S
            c * x,         // T_1
            c * x * x,
        ]; //T_2
        scalars.append(&mut x_sq); // L_vec TODO avoid append, better chaining iterators
        scalars.append(&mut x_inv_sq); // R_vec
        scalars.append(&mut value_commitment_scalars); //Value com
        scalars.push(-self.e_blinding - c * self.t_x_blinding); // B_blinding
        scalars.push(basepoint_scalar); // B
        scalars.append(&mut g); // G_vec
        scalars.append(&mut h); // H_vec
        Ok(scalars)
    }

    /// Verifies multiple aggregated rangeproofs with a single multiexponentiation
    pub fn batch_verify<T: RngCore + CryptoRng>(
        rng: &mut T,
        proofs: &[&RangeProof],
        transcripts: &mut [Transcript],
        value_commitments: &[&[CompressedRistretto]],
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        n: usize,
    ) -> Result<(), ProofError> {
        let mut all_scalars = vec![];
        let mut random_scalars = vec![];
        let mut max_m = 0;
        for ((proof, transcript), value_commitment) in proofs
            .iter()
            .zip(transcripts.iter_mut())
            .zip(value_commitments.iter())
        {
            let instance_scalars = proof.compute_verification_scalars_with_rng(
                bp_gens,
                transcript,
                value_commitment,
                n,
                rng,
            )?;
            let mut rng = transcript.build_rng().finalize(&mut thread_rng());
            random_scalars.push(Scalar::random(&mut rng));
            all_scalars.push((instance_scalars, value_commitment.len()));
        }
        let mut all_scaled_scalars = vec![];
        for ((scalars, m_i), rand_scalar) in all_scalars.iter().zip(random_scalars.iter()) {
            let scaled_scalars: Vec<Scalar> = scalars.iter().map(|s| s * rand_scalar).collect();
            all_scaled_scalars.push((scaled_scalars, *m_i));
            if *m_i > max_m {
                max_m = *m_i;
            }
        }
        let grouped_scalars = Self::group_scalars(all_scaled_scalars.as_slice(), n, max_m);

        let mut elems = vec![];
        for (proof, value_commitments) in proofs.iter().zip(value_commitments) {
            elems.push(proof.A.decompress());
            elems.push(proof.S.decompress());
            elems.push(proof.T_1.decompress());
            elems.push(proof.T_2.decompress());
            for L in proof.ipp_proof.L_vec.iter() {
                elems.push(L.decompress());
            }
            for R in proof.ipp_proof.R_vec.iter() {
                elems.push(R.decompress());
            }
            for V in value_commitments.iter() {
                elems.push(V.decompress())
            }
        }
        elems.push(Some(pc_gens.B_blinding));
        elems.push(Some(pc_gens.B));
        for G in bp_gens.G(n, max_m) {
            elems.push(Some(*G));
        }
        for H in bp_gens.H(n, max_m) {
            elems.push(Some(*H));
        }
        let mega_check = RistrettoPoint::optional_multiscalar_mul(grouped_scalars, elems)
            .ok_or_else(|| ProofError::VerificationError)?;
        if !mega_check.is_identity() {
            return Err(ProofError::VerificationError);
        }
        Ok(())
    }

    fn group_scalars(all_scalars: &[(Vec<Scalar>, usize)], n: usize, max_m: usize) -> Vec<Scalar> {
        let mut agg_scalars = vec![];
        let mut b_blind_scalars = Scalar::from(0u8);
        let mut b_scalars = Scalar::from(0u8);
        let mut g_scalars = vec![Scalar::from(0u8); n * max_m];
        let mut h_scalars = vec![Scalar::from(0u8); n * max_m];

        for (instance_scalars, m_i) in all_scalars {
            let N_i = *m_i * n; // size of this instance
            let lgN = (N_i as u64).trailing_zeros() as usize; // size of L and R vecs
                                                              // A,S,T1,T2 (4 elements) and L_vec, R_vec (lgN elemens each) + V (m_i elements)
            let k_i = 4usize + 2usize * lgN + *m_i; // number of elements unique to this instance
            for j in 0..k_i {
                agg_scalars.push(*instance_scalars.get(j as usize).unwrap());
            }
            b_blind_scalars.add_assign(&instance_scalars[k_i]);
            b_scalars.add_assign(&instance_scalars[k_i + 1]);
            for i in k_i + 2..k_i + 2 + N_i {
                g_scalars[i - k_i - 2] += instance_scalars[i];
                h_scalars[i - k_i - 2] += instance_scalars[N_i + i];
            }
        }
        agg_scalars.push(b_blind_scalars);
        agg_scalars.push(b_scalars);
        agg_scalars.append(&mut g_scalars);
        agg_scalars.append(&mut h_scalars);

        agg_scalars
    }

    /// Verifies an aggregated rangeproof for the given value commitments.
    /// This is a convenience wrapper around [`RangeProof::verify_multiple_with_rng`],
    /// passing in a threadsafe RNG.
    #[cfg(feature = "std")]
    pub fn verify_multiple(
        &self,
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        transcript: &mut Transcript,
        value_commitments: &[CompressedRistretto],
        n: usize,
    ) -> Result<(), ProofError> {
        self.verify_multiple_with_rng(
            bp_gens,
            pc_gens,
            transcript,
            value_commitments,
            n,
            &mut thread_rng(),
        )
    }

    /// Serializes the proof into a byte array of \\(2 \lg n + 9\\)
    /// 32-byte elements, where \\(n\\) is the number of secret bits.
    ///
    /// # Layout
    ///
    /// The layout of the range proof encoding is:
    ///
    /// * four compressed Ristretto points \\(A,S,T_1,T_2\\),
    /// * three scalars \\(t_x, \tilde{t}_x, \tilde{e}\\),
    /// * \\(n\\) pairs of compressed Ristretto points \\(L_0,R_0\dots,L_{n-1},R_{n-1}\\),
    /// * two scalars \\(a, b\\).
    pub fn to_bytes(&self) -> Vec<u8> {
        // 7 elements: points A, S, T1, T2, scalars tx, tx_bl, e_bl.
        let mut buf = Vec::with_capacity(7 * 32 + self.ipp_proof.serialized_size());
        buf.extend_from_slice(self.A.as_bytes());
        buf.extend_from_slice(self.S.as_bytes());
        buf.extend_from_slice(self.T_1.as_bytes());
        buf.extend_from_slice(self.T_2.as_bytes());
        buf.extend_from_slice(self.t_x.as_bytes());
        buf.extend_from_slice(self.t_x_blinding.as_bytes());
        buf.extend_from_slice(self.e_blinding.as_bytes());
        buf.extend(self.ipp_proof.to_bytes_iter());
        buf
    }

    /// Deserializes the proof from a byte slice.
    ///
    /// Returns an error if the byte slice cannot be parsed into a `RangeProof`.
    #[allow(clippy::erasing_op)]
    pub fn from_bytes(slice: &[u8]) -> Result<RangeProof, ProofError> {
        if slice.len() % 32 != 0 {
            return Err(ProofError::FormatError);
        }
        if slice.len() < 7 * 32 {
            return Err(ProofError::FormatError);
        }

        use crate::util::read32;

        let A = CompressedRistretto(read32(&slice[0 * 32..]));
        let S = CompressedRistretto(read32(&slice[1 * 32..]));
        let T_1 = CompressedRistretto(read32(&slice[2 * 32..]));
        let T_2 = CompressedRistretto(read32(&slice[3 * 32..]));

        let t_x = Scalar::from_canonical_bytes(read32(&slice[4 * 32..]))
            .ok_or(ProofError::FormatError)?;
        let t_x_blinding = Scalar::from_canonical_bytes(read32(&slice[5 * 32..]))
            .ok_or(ProofError::FormatError)?;
        let e_blinding = Scalar::from_canonical_bytes(read32(&slice[6 * 32..]))
            .ok_or(ProofError::FormatError)?;

        let ipp_proof = InnerProductProof::from_bytes(&slice[7 * 32..])?;

        Ok(RangeProof {
            A,
            S,
            T_1,
            T_2,
            t_x,
            t_x_blinding,
            e_blinding,
            ipp_proof,
        })
    }
}

impl Serialize for RangeProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes()[..])
    }
}

impl<'de> Deserialize<'de> for RangeProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RangeProofVisitor;

        impl<'de> Visitor<'de> for RangeProofVisitor {
            type Value = RangeProof;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter.write_str("a valid RangeProof")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<RangeProof, E>
            where
                E: serde::de::Error,
            {
                // Using Error::custom requires T: Display, which our error
                // type only implements when it implements std::error::Error.
                #[cfg(feature = "std")]
                return RangeProof::from_bytes(v).map_err(serde::de::Error::custom);
                // In no-std contexts, drop the error message.
                #[cfg(not(feature = "std"))]
                return RangeProof::from_bytes(v)
                    .map_err(|_| serde::de::Error::custom("deserialization error"));
            }
        }

        deserializer.deserialize_bytes(RangeProofVisitor)
    }
}

/// Compute
/// \\[
/// \delta(y,z) = (z - z^{2}) \langle \mathbf{1}, {\mathbf{y}}^{n \cdot m} \rangle - \sum_{j=0}^{m-1} z^{j+3} \cdot \langle \mathbf{1}, {\mathbf{2}}^{n \cdot m} \rangle
/// \\]
fn delta(n: usize, m: usize, y: &Scalar, z: &Scalar) -> Scalar {
    let sum_y = util::sum_of_powers(y, n * m);
    let sum_2 = util::sum_of_powers(&Scalar::from(2u64), n);
    let sum_z = util::sum_of_powers(z, m);

    (z - z * z) * sum_y - z * z * z * sum_2 * sum_z
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::generators::PedersenGens;

    #[test]
    fn test_delta() {
        let mut rng = rand::thread_rng();
        let y = Scalar::random(&mut rng);
        let z = Scalar::random(&mut rng);

        // Choose n = 256 to ensure we overflow the group order during
        // the computation, to check that that's done correctly
        let n = 256;

        // code copied from previous implementation
        let z2 = z * z;
        let z3 = z2 * z;
        let mut power_g = Scalar::zero();
        let mut exp_y = Scalar::one(); // start at y^0 = 1
        let mut exp_2 = Scalar::one(); // start at 2^0 = 1
        for _ in 0..n {
            power_g += (z - z2) * exp_y - z3 * exp_2;

            exp_y = exp_y * y; // y^i -> y^(i+1)
            exp_2 = exp_2 + exp_2; // 2^i -> 2^(i+1)
        }

        assert_eq!(power_g, delta(n, 1, &y, &z),);
    }

    /// Given a bitsize `n`, test the following:
    ///
    /// 1. Generate `m` random values and create a proof they are all in range;
    /// 2. Serialize to wire format;
    /// 3. Deserialize from wire format;
    /// 4. Verify the proof.
    fn singleparty_create_and_verify_helper(n: usize, m: usize) {
        // Split the test into two scopes, so that it's explicit what
        // data is shared between the prover and the verifier.

        // Use bincode for serialization
        //use bincode; // already present in lib.rs

        // Both prover and verifier have access to the generators and the proof
        let max_bitsize = 64;
        let max_parties = 8;
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(max_bitsize, max_parties);

        // Prover's scope
        let (proof_bytes, value_commitments) = {
            use self::rand::Rng;
            let mut rng = rand::thread_rng();

            // 0. Create witness data
            let (min, max) = (0u64, ((1u128 << n) - 1) as u64);
            let values: Vec<u64> = (0..m).map(|_| rng.gen_range(min, max)).collect();
            let blindings: Vec<Scalar> = (0..m).map(|_| Scalar::random(&mut rng)).collect();

            // 1. Create the proof
            let mut transcript = Transcript::new(b"AggregatedRangeProofTest");
            let (proof, value_commitments) = RangeProof::prove_multiple(
                &bp_gens,
                &pc_gens,
                &mut transcript,
                &values,
                &blindings,
                n,
            )
            .unwrap();

            // 2. Return serialized proof and value commitments
            (bincode::serialize(&proof).unwrap(), value_commitments)
        };

        // Verifier's scope
        {
            // 3. Deserialize
            let proof: RangeProof = bincode::deserialize(&proof_bytes).unwrap();

            // 4. Verify with the same customization label as above
            let mut transcript = Transcript::new(b"AggregatedRangeProofTest");

            assert!(proof
                .verify_multiple(&bp_gens, &pc_gens, &mut transcript, &value_commitments, n)
                .is_ok());
        }
    }

    /// Given a bitsize `n`, test the following:
    ///
    /// 1. Generate `m` random values and create a proof they are all in range;
    /// 2. Serialize to wire format;
    /// 3. Deserialize from wire format;
    /// 4. Verify the proof.
    fn singleparty_create_and_verify_helper_batch(n: usize, m: &[usize]) {
        // Split the test into two scopes, so that it's explicit what
        // data is shared between the prover and the verifier.

        // Both prover and verifier have access to the generators and the proof
        let max_bitsize = n;
        let max_parties = m.iter().fold(0, |ac, m_i| ac.max(*m_i));
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(max_bitsize, max_parties);

        let mut proofs_bytes = vec![];
        let mut all_value_commitments = vec![];

        for m_i in m {
            // Prover's scope
            let mut transcript = Transcript::new(b"AggregatedRangeProofTest");
            let (proof_bytes, value_commitments) = {
                use rand::Rng;
                let mut rng = rand::thread_rng();

                // 0. Create witness data
                let (min, max) = (0u64, ((1u128 << n) - 1) as u64);
                let values: Vec<u64> = (0..*m_i).map(|_| rng.gen_range(min, max)).collect();
                let blindings: Vec<Scalar> = (0..*m_i).map(|_| Scalar::random(&mut rng)).collect();

                // 1. Create the proof
                let (proof, value_commitments) = RangeProof::prove_multiple(
                    &bp_gens,
                    &pc_gens,
                    &mut transcript,
                    &values,
                    &blindings,
                    n,
                )
                .unwrap();

                // 2. Return serialized proof and value commitments
                (bincode::serialize(&proof).unwrap(), value_commitments)
            };
            proofs_bytes.push(proof_bytes);
            all_value_commitments.push(value_commitments);
        }

        // Verifier's scope
        {
            let mut transcripts = vec![];
            let mut proofs = vec![];
            let mut commitments = vec![];
            for (proof_bytes, instance_commitments) in
                proofs_bytes.iter().zip(all_value_commitments.iter())
            {
                // 3. Deserialize

                let proof: RangeProof = bincode::deserialize(&proof_bytes).unwrap();

                // 4. Verify with the same customization label as above
                let transcript = Transcript::new(b"AggregatedRangeProofTest");

                proofs.push(proof);
                transcripts.push(transcript);
                commitments.push(instance_commitments.as_slice());
            }
            assert!(super::RangeProof::batch_verify(
                &mut rand::thread_rng(),
                &proofs.iter().collect::<Vec<_>>(),
                transcripts.as_mut_slice(),
                commitments.as_slice(),
                &bp_gens,
                &pc_gens,
                n
            )
            .is_ok());
        }
    }

    #[test]
    fn create_and_verify_n_32_m_1() {
        singleparty_create_and_verify_helper(32, 1);
    }

    #[test]
    fn create_and_verify_n_32_m_2() {
        singleparty_create_and_verify_helper(32, 2);
    }

    #[test]
    fn create_and_verify_n_32_m_4() {
        singleparty_create_and_verify_helper(32, 4);
    }

    #[test]
    fn create_and_verify_n_32_m_8() {
        singleparty_create_and_verify_helper(32, 8);
    }

    #[test]
    fn create_and_verify_n_64_m_1() {
        singleparty_create_and_verify_helper(64, 1);
    }

    #[test]
    fn create_and_verify_n_64_m_2() {
        singleparty_create_and_verify_helper(64, 2);
    }

    #[test]
    fn create_and_verify_n_64_m_4() {
        singleparty_create_and_verify_helper(64, 4);
    }

    #[test]
    fn create_and_verify_n_64_m_8() {
        singleparty_create_and_verify_helper(64, 8);
    }

    #[test]
    fn create_and_verify_n_32_batch() {
        singleparty_create_and_verify_helper_batch(32, &[2, 4, 2, 8]);
    }

    #[test]
    fn create_and_verify_n_64_batch() {
        singleparty_create_and_verify_helper_batch(32, &[16, 8, 2, 4, 32]);
    }

    #[test]
    fn detect_dishonest_party_during_aggregation() {
        use self::dealer::*;
        use self::party::*;

        use crate::errors::MPCError;

        // Simulate four parties, two of which will be dishonest and use a 64-bit value.
        let m = 4;
        let n = 32;

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(n, m);

        use self::rand::Rng;
        let mut rng = rand::thread_rng();
        let mut transcript = Transcript::new(b"AggregatedRangeProofTest");

        // Parties 0, 2 are honest and use a 32-bit value
        let v0 = rng.gen::<u32>() as u64;
        let v0_blinding = Scalar::random(&mut rng);
        let party0 = Party::new(&bp_gens, &pc_gens, v0, v0_blinding, n).unwrap();

        let v2 = rng.gen::<u32>() as u64;
        let v2_blinding = Scalar::random(&mut rng);
        let party2 = Party::new(&bp_gens, &pc_gens, v2, v2_blinding, n).unwrap();

        // Parties 1, 3 are dishonest and use a 64-bit value
        let v1 = rng.gen::<u64>();
        let v1_blinding = Scalar::random(&mut rng);
        let party1 = Party::new(&bp_gens, &pc_gens, v1, v1_blinding, n).unwrap();

        let v3 = rng.gen::<u64>();
        let v3_blinding = Scalar::random(&mut rng);
        let party3 = Party::new(&bp_gens, &pc_gens, v3, v3_blinding, n).unwrap();

        let dealer = Dealer::new(&bp_gens, &pc_gens, &mut transcript, n, m).unwrap();

        let (party0, bit_com0) = party0.assign_position(0).unwrap();
        let (party1, bit_com1) = party1.assign_position(1).unwrap();
        let (party2, bit_com2) = party2.assign_position(2).unwrap();
        let (party3, bit_com3) = party3.assign_position(3).unwrap();

        let (dealer, bit_challenge) = dealer
            .receive_bit_commitments(vec![bit_com0, bit_com1, bit_com2, bit_com3])
            .unwrap();

        let (party0, poly_com0) = party0.apply_challenge(&bit_challenge);
        let (party1, poly_com1) = party1.apply_challenge(&bit_challenge);
        let (party2, poly_com2) = party2.apply_challenge(&bit_challenge);
        let (party3, poly_com3) = party3.apply_challenge(&bit_challenge);

        let (dealer, poly_challenge) = dealer
            .receive_poly_commitments(vec![poly_com0, poly_com1, poly_com2, poly_com3])
            .unwrap();

        let share0 = party0.apply_challenge(&poly_challenge).unwrap();
        let share1 = party1.apply_challenge(&poly_challenge).unwrap();
        let share2 = party2.apply_challenge(&poly_challenge).unwrap();
        let share3 = party3.apply_challenge(&poly_challenge).unwrap();

        match dealer.receive_shares(&[share0, share1, share2, share3]) {
            Err(MPCError::MalformedProofShares { bad_shares }) => {
                assert_eq!(bad_shares, vec![1, 3]);
            }
            Err(_) => {
                panic!("Got wrong error type from malformed shares");
            }
            Ok(_) => {
                panic!("The proof was malformed, but it was not detected");
            }
        }
    }

    #[test]
    fn detect_dishonest_dealer_during_aggregation() {
        use self::dealer::*;
        use self::party::*;
        use crate::errors::MPCError;

        // Simulate one party
        let m = 1;
        let n = 32;

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(n, m);

        use self::rand::Rng;
        let mut rng = rand::thread_rng();
        let mut transcript = Transcript::new(b"AggregatedRangeProofTest");

        let v0 = rng.gen::<u32>() as u64;
        let v0_blinding = Scalar::random(&mut rng);
        let party0 = Party::new(&bp_gens, &pc_gens, v0, v0_blinding, n).unwrap();

        let dealer = Dealer::new(&bp_gens, &pc_gens, &mut transcript, n, m).unwrap();

        // Now do the protocol flow as normal....

        let (party0, bit_com0) = party0.assign_position(0).unwrap();

        let (dealer, bit_challenge) = dealer.receive_bit_commitments(vec![bit_com0]).unwrap();

        let (party0, poly_com0) = party0.apply_challenge(&bit_challenge);

        let (_dealer, mut poly_challenge) =
            dealer.receive_poly_commitments(vec![poly_com0]).unwrap();

        // But now simulate a malicious dealer choosing x = 0
        poly_challenge.x = Scalar::zero();

        let maybe_share0 = party0.apply_challenge(&poly_challenge);

        assert!(maybe_share0.unwrap_err() == MPCError::MaliciousDealer);
    }
}
