//! Defines a `TranscriptProtocol` trait for using a Merlin transcript.

use crate::curve::canaan::{Fr, G1Affine};
use ark_ff::to_bytes;
use ark_std::{rand::SeedableRng, UniformRand, Zero};
use merlin::Transcript;
use rand_chacha::ChaChaRng;

use crate::errors::ProofError;

pub trait TranscriptProtocol {
    /// Append a domain separator for an `n`-bit, `m`-party range proof.
    fn rangeproof_domain_sep(&mut self, n: u64, m: u64);

    /// Append a domain separator for a length-`n` inner product proof.
    fn innerproduct_domain_sep(&mut self, n: u64);

    /// Append a domain separator for a constraint system.
    fn r1cs_domain_sep(&mut self);

    /// Commit a domain separator for a CS without randomized constraints.
    fn r1cs_1phase_domain_sep(&mut self);

    /// Commit a domain separator for a CS with randomized constraints.
    fn r1cs_2phase_domain_sep(&mut self);

    /// Append a `scalar` with the given `label`.
    fn append_scalar(&mut self, label: &'static [u8], scalar: &Fr);

    /// Append a `point` with the given `label`.
    fn append_point(&mut self, label: &'static [u8], point: &G1Affine);

    /// Check that a point is not the identity, then append it to the
    /// transcript.  Otherwise, return an error.
    fn validate_and_append_point(
        &mut self,
        label: &'static [u8],
        point: &G1Affine,
    ) -> Result<(), ProofError>;

    /// Compute a `label`ed challenge variable.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Fr;
}

impl TranscriptProtocol for Transcript {
    fn rangeproof_domain_sep(&mut self, n: u64, m: u64) {
        self.append_message(b"dom-sep", b"rangeproof v1");
        self.append_u64(b"n", n);
        self.append_u64(b"m", m);
    }

    fn innerproduct_domain_sep(&mut self, n: u64) {
        self.append_message(b"dom-sep", b"ipp v1");
        self.append_u64(b"n", n);
    }

    fn r1cs_domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"r1cs v1");
    }

    fn r1cs_1phase_domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"r1cs-1phase");
    }

    fn r1cs_2phase_domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"r1cs-2phase");
    }

    fn append_scalar(&mut self, label: &'static [u8], scalar: &Fr) {
        self.append_message(label, &to_bytes!(scalar).unwrap());
    }

    fn append_point(&mut self, label: &'static [u8], point: &G1Affine) {
        self.append_message(label, &to_bytes!(point).unwrap());
    }

    fn validate_and_append_point(
        &mut self,
        label: &'static [u8],
        point: &G1Affine,
    ) -> Result<(), ProofError> {
        if point.is_zero() {
            Err(ProofError::VerificationError)
        } else {
            Ok(self.append_message(label, &to_bytes!(point)?))
        }
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> Fr {
        let mut buf = [0u8; 32];
        self.challenge_bytes(label, &mut buf);

        let mut prng = ChaChaRng::from_seed(buf);
        Fr::rand(&mut prng)
    }
}
