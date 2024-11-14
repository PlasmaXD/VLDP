//! R1CS constraint generation for parameters that are generic across each VLDP scheme.

use crate::prelude::{constraints::*, *};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{Namespace, SynthesisError};
use std::borrow::Borrow;
use std::cmp::Ordering;

/// R1CS variable for storing the gamma variable (for the LDP randomizers, see paper Sec. 4.1)
pub struct GammaVar<Conf: Config> {
    gamma: FpVar<ConstraintField<Conf>>,
}

impl<Conf: Config> GammaVar<Conf> {
    /// Given an array of random bytes this computes Ber(gamma) inside the ZKP circuit.
    pub fn compute_ldp_bit(
        &self,
        randomness: &[UInt8<ConstraintField<Conf>>],
    ) -> Result<Boolean<ConstraintField<Conf>>, SynthesisError> {
        let randomness = Boolean::le_bits_to_fp_var(&randomness.to_bits_le()?)?;
        // randomness <= gamma
        self.gamma
            .is_cmp_unchecked(&randomness, Ordering::Greater, true)
    }
}

// R1CS variable allocation for gamma
impl<Conf: Config, const N: usize> AllocVar<[u8; N], ConstraintField<Conf>> for GammaVar<Conf> {
    fn new_variable<T: Borrow<[u8; N]>>(
        cs: impl Into<Namespace<ConstraintField<Conf>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            gamma: FpVar::new_variable(
                cs,
                || {
                    f().map(|gamma| {
                        ConstraintField::<Conf>::from_le_bytes_mod_order(gamma.borrow())
                    })
                },
                mode,
            )?,
        })
    }
}
