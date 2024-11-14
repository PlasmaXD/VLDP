//! Structs and basic logic for all messages that are sent between clients and server in the
//! Base VLDP scheme.

use crate::prelude::*;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Message sent by client in the `GenRand` step of the paper.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct GenerateRandomnessMessageClientBase<Conf: Config, const TIME_BYTES: usize>
where
    ClientCommitmentSchemeOutput<Conf>: CanonicalDeserialize,
    ClientSignatureSchemePublicKey<Conf>: CanonicalDeserialize,
{
    pub client_randomness_commitment: ClientCommitmentSchemeOutput<Conf>,
    pub client_signature_public_key: ClientSignatureSchemePublicKey<Conf>,
    pub time: [u8; TIME_BYTES],
}

/// Message sent by the server in the `GenRand` step of the paper.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct GenerateRandomnessMessageServerBase<Conf: Config>
where
    ServerSignatureSchemeSignature<Conf>: CanonicalDeserialize,
{
    pub server_seed: PRFSchemeSeed<Conf>,
    pub server_signature: ServerSignatureSchemeSignature<Conf>,
}

/// Message that is to be signed by the server as part of the `GenRand` step of the paper.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct GenerateRandomnessSignatureInputBase<Conf: Config>
where
    ClientCommitmentSchemeOutput<Conf>: CanonicalDeserialize,
    ClientSignatureSchemePublicKey<Conf>: CanonicalDeserialize,
{
    pub client_randomness_commitment: ClientCommitmentSchemeOutput<Conf>,
    pub client_signature_public_key: ClientSignatureSchemePublicKey<Conf>,
    pub server_seed: PRFSchemeSeed<Conf>,
}

impl<Conf: Config> GenerateRandomnessSignatureInputBase<Conf>
where
    ClientCommitmentSchemeOutput<Conf>: CanonicalDeserialize,
    ClientSignatureSchemePublicKey<Conf>: CanonicalDeserialize,
{
    /// Create signature input message from the received client message and the server seed.
    pub fn new<const TIME_BYTES: usize>(
        client_message: GenerateRandomnessMessageClientBase<Conf, TIME_BYTES>,
        server_seed: PRFSchemeSeed<Conf>,
    ) -> Self {
        Self {
            client_randomness_commitment: client_message.client_randomness_commitment,
            client_signature_public_key: client_message.client_signature_public_key,
            server_seed,
        }
    }
}

/// Message sent by the client as part of the `Randomize` step of the paper.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifiableRandomizationMessageBase<Conf: Config, const INPUT_BYTES: usize>
where
    Proof<Conf>: CanonicalDeserialize,
    ClientCommitmentSchemeOutput<Conf>: CanonicalDeserialize,
    ClientSignatureSchemePublicKey<Conf>: CanonicalDeserialize,
    ServerSignatureSchemeSignature<Conf>: CanonicalDeserialize,
{
    pub client_sig_pk: ClientSignatureSchemePublicKey<Conf>,
    pub client_randomness_commitment: ClientCommitmentSchemeOutput<Conf>,
    pub server_seed: PRFSchemeSeed<Conf>,
    pub server_signature: ServerSignatureSchemeSignature<Conf>,
    pub proof: Proof<Conf>,
    pub ldp_value: u64,
}
