//! Structs and basic logic for all messages that are sent between clients and server in the
//! Shuffle VLDP scheme.

use crate::prelude::*;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Message sent by client in the `GenRand` step of the paper.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct GenerateRandomnessMessageClientShuffle<Conf: Config>
where
    ClientCommitmentSchemeOutput<Conf>: CanonicalDeserialize,
    ClientSignatureSchemePublicKey<Conf>: CanonicalDeserialize,
{
    pub client_seed_commitment: ClientCommitmentSchemeOutput<Conf>,
    pub client_signature_public_key: ClientSignatureSchemePublicKey<Conf>,
}

/// Message sent by the server in the `GenRand` step of the paper.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct GenerateRandomnessMessageServerShuffle<Conf: Config>
where
    ServerSignatureSchemeSignature<Conf>: CanonicalDeserialize,
{
    pub server_seed: PRFSchemeSeed<Conf>,
    pub server_signature: ServerSignatureSchemeSignature<Conf>,
}

/// Message that is to be signed by the server as part of the `GenRand` step of the paper.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct GenerateRandomnessSignatureInputShuffle<Conf: Config>
where
    ClientCommitmentSchemeOutput<Conf>: CanonicalDeserialize,
    ClientSignatureSchemePublicKey<Conf>: CanonicalDeserialize,
{
    pub client_seed_commitment: ClientCommitmentSchemeOutput<Conf>,
    pub client_signature_public_key: ClientSignatureSchemePublicKey<Conf>,
    pub server_seed: PRFSchemeSeed<Conf>,
}

impl<Conf: Config> GenerateRandomnessSignatureInputShuffle<Conf>
where
    ClientCommitmentSchemeOutput<Conf>: CanonicalDeserialize,
    ClientSignatureSchemePublicKey<Conf>: CanonicalDeserialize,
{
    /// Create signature input message from the received client message and the server seed.
    pub fn new(
        client_message: GenerateRandomnessMessageClientShuffle<Conf>,
        server_seed: PRFSchemeSeed<Conf>,
    ) -> Self {
        Self {
            client_seed_commitment: client_message.client_seed_commitment,
            client_signature_public_key: client_message.client_signature_public_key,
            server_seed,
        }
    }
}

/// Message sent by the client as part of the `Randomize` step of the paper.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifiableRandomizationMessageShuffle<Conf: Config, const INPUT_BYTES: usize>
where
    Proof<Conf>: CanonicalDeserialize,
{
    pub proof: Proof<Conf>,
    pub ldp_value: u64,
}
