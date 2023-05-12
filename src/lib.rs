#![cfg_attr(not(feature = "std"), no_std)]

pub mod curve;

mod util;

mod errors;
mod generators;
mod inner_product_proof;
mod transcript;

pub use crate::errors::ProofError;
pub use crate::generators::{BulletproofGens, BulletproofGensShare, PedersenGens};

#[cfg(feature = "yoloproofs")]
pub mod r1cs;
