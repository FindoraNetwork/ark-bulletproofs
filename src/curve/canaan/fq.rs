use ark_ff::fields::{Fp320, MontBackend, MontConfig};

#[derive(MontConfig)]
#[modulus = "115792089237316195423570985008687907853634386693684621307141857813043191627553"]
#[generator = "5"]
pub struct FqConfig;
pub type Fq = Fp320<MontBackend<FqConfig, 5>>;
