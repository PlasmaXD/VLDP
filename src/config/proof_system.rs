//! In this file we define a generic proof system struct that makes it easier for future
//! adaptations to switch the Groth16 proof system we used for another one.

use crate::prelude::*;
use ark_ff::PrimeField;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_serialize::CanonicalSerialize;
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;

/// Some proof systems need a specifically defined RNG, this trait helps to make that generic.
pub trait ProofSystemRng: RngCore {
    fn new() -> Self;
}

impl ProofSystemRng for ChaChaRng {
    fn new() -> Self {
        Self::from_entropy()
    }
}

/// Generic trait for a ZKP scheme. This makes it easier to switch out different ZKP schemes without
/// having to write much code. (Currently, only implemented for Groth16.)
pub trait ProofSystem<R: ProofSystemRng> {
    type ConstraintField: PrimeField;
    type ProvingKey: Clone;
    type VerifyingKey: Clone;
    type Proof: CanonicalSerialize + Default;

    fn keygen<C: ConstraintSynthesizer<Self::ConstraintField> + Clone>(
        circuit: C,
        rng: &mut R,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Error>;

    fn prove<C: ConstraintSynthesizer<Self::ConstraintField>>(
        proving_key: &Self::ProvingKey,
        circuit: C,
        rng: &mut R,
    ) -> Result<Self::Proof, Error>;

    fn verify(
        verifying_key: &Self::VerifyingKey,
        public_inputs: &[Self::ConstraintField],
        proof: &Self::Proof,
        rng: &mut R,
    ) -> Result<bool, Error>;
}

// HERE WE IMPLEMENT THE GENERIC TRAIT FOR GROTH16 (as used in our experiments)
impl<E: Pairing, QAP: ark_groth16::r1cs_to_qap::R1CSToQAP, R: ProofSystemRng + CryptoRng>
    ProofSystem<R> for ark_groth16::Groth16<E, QAP>
{
    type ConstraintField = E::ScalarField;
    type ProvingKey = ark_groth16::ProvingKey<E>;
    type VerifyingKey = ark_groth16::PreparedVerifyingKey<E>;
    type Proof = ark_groth16::Proof<E>;

    fn keygen<C: ConstraintSynthesizer<Self::ConstraintField>>(
        circuit: C,
        rng: &mut R,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Error> {
        let (pk, vk) = ark_groth16::Groth16::<E, QAP>::setup(circuit, rng)?;

        #[cfg(feature = "print-trace")]
        {
            println!("Proving key size: {}b", pk.compressed_size());
            println!("Verifying key size: {}b", vk.compressed_size());
        }

        let pvk = ark_groth16::prepare_verifying_key(&vk);
        Ok((pk, pvk))
    }

    fn prove<C: ConstraintSynthesizer<Self::ConstraintField>>(
        proving_key: &Self::ProvingKey,
        circuit: C,
        rng: &mut R,
    ) -> Result<Self::Proof, Error> {
        Ok(<ark_groth16::Groth16<E, QAP> as SNARK<
            Self::ConstraintField,
        >>::prove(proving_key, circuit, rng)?)
    }

    fn verify(
        verifying_key: &Self::VerifyingKey,
        public_inputs: &[Self::ConstraintField],
        proof: &Self::Proof,
        _rng: &mut R,
    ) -> Result<bool, Error> {
        Ok(ark_groth16::Groth16::<E>::verify_with_processed_vk(
            verifying_key,
            &public_inputs,
            proof,
        )?)
    }
}
