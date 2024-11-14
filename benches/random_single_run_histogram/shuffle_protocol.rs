//! Perform a benchmark with a random input of the Shuffle VLDP scheme, for the parameters given in
//! the files specified in lines 21-26.
//!
//! Runs a number of warmup executions, before running the actual requested number of  measurements.
//! These numbers can be specified in the files mentioned on  line 16-17.

use ark_bls12_381::Bls12_381;
use ark_ed_on_bls12_381::constraints::EdwardsVar as JubJubVar;
use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
use ark_groth16::Groth16;
use astro_float::BigFloat;
use rand_chacha::ChaChaRng;
use vldp::config::{BasicConfig, BasicConfigGadget};
use vldp::run_random::*;

const N_WARMUP: u8 = include!("../parameters/n_warmup");
const N_MEASURE: u8 = include!("../parameters/n_measure");

fn main() {
    // protocol settings
    const INPUT_BYTES: usize = include!("../parameters/input_bytes");
    const TIME_BYTES: usize = include!("../parameters/time_bytes");
    const GAMMA_BYTES: usize = include!("../parameters/gamma_bytes");
    const K: u64 = 8;
    const IS_REAL_INPUT: bool = false;
    const RANDOMNESS_BYTES: usize = include!("../parameters/randomness_bytes");

    // gamma value
    let gamma_value = 0.5;
    let gamma = BigFloat::from_f64(gamma_value, GAMMA_BYTES * 8);

    // curve selection
    type PairingCurve = Bls12_381;
    type InnerCurve = JubJub;
    type InnerCurveVar = JubJubVar;

    // zkp scheme selection
    type ZKPRng = ChaChaRng;
    type ZKPScheme = Groth16<PairingCurve>;

    // WARM UP
    println!("--- START WARMUP ---");
    for _ in 0..N_WARMUP {
        run_protocol_shuffle::<
            BasicConfig<InnerCurve, ZKPRng, ZKPScheme, 32>,
            BasicConfigGadget<InnerCurve, InnerCurveVar>,
            INPUT_BYTES,
            TIME_BYTES,
            GAMMA_BYTES,
            RANDOMNESS_BYTES,
            K,
            IS_REAL_INPUT,
        >(gamma.clone())
        .unwrap()
    }
    println!("--- END WARMUP ---");

    // MEASUREMENTS
    println!("--- START MEASUREMENTS ---");
    for _ in 0..N_MEASURE {
        run_protocol_shuffle::<
            BasicConfig<InnerCurve, ZKPRng, ZKPScheme, 32>,
            BasicConfigGadget<InnerCurve, InnerCurveVar>,
            INPUT_BYTES,
            TIME_BYTES,
            GAMMA_BYTES,
            RANDOMNESS_BYTES,
            K,
            IS_REAL_INPUT,
        >(gamma.clone())
        .unwrap()
    }
    println!("--- END MEASUREMENTS ---");
}
