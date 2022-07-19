#![cfg_attr(not(feature = "std"), no_std)]

pub mod curve;

mod util;

mod errors;
mod generators;
mod inner_product_proof;
mod transcript;

pub use crate::errors::ProofError;
pub use crate::generators::{BulletproofGens, BulletproofGensShare, PedersenGens};

mod range_proof;
pub use crate::range_proof::RangeProof;

pub mod range_proof_mpc {
    pub use crate::errors::MPCError;
    pub use crate::range_proof::dealer;
    pub use crate::range_proof::messages;
    pub use crate::range_proof::party;
}

mod notes {
    mod inner_product_proof {}
    mod range_proof {}
    mod r1cs_proof {}
}

#[cfg(feature = "yoloproofs")]
#[cfg(feature = "std")]
pub mod r1cs;
