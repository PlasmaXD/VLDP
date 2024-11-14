//! Generic definitions for ZKP constraints for signature verification for a signature scheme.
//!
//! This file was adapted from (we required differing specifications):
//! https://github.com/arkworks-rs/r1cs-tutorial/blob/main/simple-payments/src/signature/constraints.rs

use crate::prelude::*;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;

use crate::primitives::signature::SignatureScheme;

/// R1CS gadget for signature verification inside ZKP circuits.
pub trait SigVerifyGadget<S: SignatureScheme, ConstraintF: Field> {
    type ParametersVar: AllocVar<S::Parameters, ConstraintF> + Clone;

    type PublicKeyVar: ToBytesGadget<ConstraintF> + AllocVar<S::PublicKey, ConstraintF> + Clone;

    type SignatureVar: ToBytesGadget<ConstraintF> + AllocVar<S::Signature, ConstraintF> + Clone;

    fn verify(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        message: &[UInt8<ConstraintF>],
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError>;
}

#[cfg(test)]
mod test {
    use crate::prelude::SignatureScheme;
    use crate::primitives::crh::blake2s::constraints::Blake2s256Gadget;
    use crate::primitives::crh::Blake2s256;
    use crate::primitives::signature::schnorr::constraints::SchnorrSignatureVerifyGadget;
    use crate::primitives::signature::{Schnorr, SigVerifyGadget};
    use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
    use ark_crypto_primitives::crh::sha256::Sha256;
    use ark_ec::CurveGroup;
    use ark_ed_on_bls12_381::constraints::EdwardsVar as JubJubVar;
    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
    use ark_ff::PrimeField;
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;

    fn sign_and_verify<F: PrimeField, S: SignatureScheme, SG: SigVerifyGadget<S, F>>(
        message: &[u8],
    ) {
        let rng = &mut test_rng();
        let parameters = S::setup::<_>(rng).unwrap();
        let (pk, sk) = S::keygen(&parameters, rng).unwrap();
        let sig = S::sign(&parameters, &sk, &message, rng).unwrap();
        assert!(S::verify(&parameters, &pk, &message, &sig).unwrap());

        let cs = ConstraintSystem::<F>::new_ref();

        let parameters_var = SG::ParametersVar::new_constant(cs.clone(), parameters).unwrap();
        let signature_var = SG::SignatureVar::new_witness(cs.clone(), || Ok(&sig)).unwrap();
        let pk_var = SG::PublicKeyVar::new_witness(cs.clone(), || Ok(&pk)).unwrap();
        let msg_var = UInt8::new_witness_vec(
            cs.clone(),
            message
                .iter()
                .map(|&x| Some(x))
                .collect::<Vec<_>>()
                .as_slice(),
        )
        .unwrap();
        let valid_sig_var = SG::verify(&parameters_var, &pk_var, &msg_var, &signature_var).unwrap();

        valid_sig_var.enforce_equal(&Boolean::<F>::TRUE).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    fn failed_verification<S: SignatureScheme>(message: &[u8], bad_message: &[u8]) {
        let rng = &mut test_rng();
        let parameters = S::setup::<_>(rng).unwrap();
        let (pk, sk) = S::keygen(&parameters, rng).unwrap();
        let sig = S::sign(&parameters, &sk, message, rng).unwrap();
        assert!(!S::verify(&parameters, &pk, bad_message, &sig).unwrap());
    }

    #[test]
    fn schnorr_signature_test() {
        type F = <JubJub as CurveGroup>::BaseField;
        let message = "Hi, I am a Schnorr signature!";
        sign_and_verify::<
            F,
            Schnorr<JubJub, Sha256>,
            SchnorrSignatureVerifyGadget<JubJub, JubJubVar, Sha256, Sha256Gadget<F>>,
        >(message.as_bytes());
        failed_verification::<Schnorr<JubJub, Sha256>>(
            message.as_bytes(),
            "Bad message".as_bytes(),
        );

        let message = "Hi, I am a Schnorr signature!";
        sign_and_verify::<
            F,
            Schnorr<JubJub, Blake2s256>,
            SchnorrSignatureVerifyGadget<JubJub, JubJubVar, Blake2s256, Blake2s256Gadget>,
        >(message.as_bytes());
        failed_verification::<Schnorr<JubJub, Blake2s256>>(
            message.as_bytes(),
            "Bad message".as_bytes(),
        );
    }
}
