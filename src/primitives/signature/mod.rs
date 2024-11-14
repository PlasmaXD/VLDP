//! Generic definition of a signature scheme, also contains the constraints for usage inside ZKP
//! circuits.
//!
//! This file was adapted from (we required differing specifications):
//! https://github.com/arkworks-rs/r1cs-tutorial/blob/main/simple-payments/src/signature/mod.rs

use crate::prelude::*;
use ark_serialize::CanonicalSerialize;
use ark_std::hash::Hash;

// ZKP constraints
pub mod constraints;
pub use constraints::*;

// Schnorr scheme
pub mod schnorr;
pub use schnorr::*;

/// Generic definition of a Signature Scheme
pub trait SignatureScheme {
    type Parameters: Clone + Send + Sync;
    type PublicKey: CanonicalSerialize + Hash + Eq + Clone + Default + Send + Sync;
    type SecretKey: CanonicalSerialize + Clone + Default;
    type Signature: CanonicalSerialize + Clone + Default + Send + Sync;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error>;

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error>;

    fn sign<R: Rng>(
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, Error>;

    fn verify(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, Error>;
}

#[cfg(test)]
mod test {
    use crate::prelude::SignatureScheme;
    use crate::primitives::crh::Blake2s256;
    use crate::primitives::signature::Schnorr;
    use ark_crypto_primitives::crh::sha256::Sha256;
    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
    use ark_std::test_rng;

    fn sign_and_verify<S: SignatureScheme>(message: &[u8]) {
        let rng = &mut test_rng();
        let parameters = S::setup::<_>(rng).unwrap();
        let (pk, sk) = S::keygen(&parameters, rng).unwrap();
        let sig = S::sign(&parameters, &sk, &message, rng).unwrap();
        assert!(S::verify(&parameters, &pk, &message, &sig).unwrap());
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
        let message = "Hi, I am a Schnorr signature!";
        sign_and_verify::<Schnorr<JubJub, Sha256>>(message.as_bytes());
        failed_verification::<Schnorr<JubJub, Sha256>>(
            message.as_bytes(),
            "Bad message".as_bytes(),
        );

        sign_and_verify::<Schnorr<JubJub, Blake2s256>>(message.as_bytes());
        failed_verification::<Schnorr<JubJub, Blake2s256>>(
            message.as_bytes(),
            "Bad message".as_bytes(),
        );
    }
}
