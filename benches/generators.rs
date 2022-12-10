#![allow(deprecated)]

use ark_bulletproofs::{BulletproofGens, PedersenGens};
use ark_secq256k1::Affine;

#[macro_use]
extern crate criterion;
use criterion::Criterion;

fn pc_gens(c: &mut Criterion) {
    c.bench_function("PedersenGens::new", |b| {
        b.iter(|| PedersenGens::<Affine>::default())
    });
}

fn bp_gens(c: &mut Criterion) {
    c.bench_function_over_inputs(
        "BulletproofGens::new",
        |b, size| b.iter(|| BulletproofGens::<Affine>::new(*size, 1)),
        (0..10).map(|i| 2 << i),
    );
}

criterion_group! {
    bp,
    bp_gens,
    pc_gens,
}

criterion_main!(bp);
