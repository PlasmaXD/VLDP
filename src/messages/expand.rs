//! Structs and basic logic for all messages that are sent between clients and server in the
//! Expand VLDP scheme.

use crate::prelude::*;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Message sent by client in the `GenRand` step of the paper.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct GenerateRandomnessMessageClientExpand<Conf: Config>
where
    ClientSignatureSchemePublicKey<Conf>: CanonicalDeserialize,
{
    pub client_merkle_tree_root: ClientMerkleTreeRoot<Conf>,
    pub client_signature_public_key: ClientSignatureSchemePublicKey<Conf>,
}

/// Message sent by the server in the `GenRand` step of the paper.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct GenerateRandomnessMessageServerExpand<Conf: Config>
where
    ServerSignatureSchemeSignature<Conf>: CanonicalDeserialize,
{
    pub server_seed: PRFSchemeSeed<Conf>,
    pub server_signature: ServerSignatureSchemeSignature<Conf>,
}

/// Message that is to be signed by the server as part of the `GenRand` step of the paper.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct GenerateRandomnessSignatureInputExpand<Conf: Config>
where
    ClientSignatureSchemePublicKey<Conf>: CanonicalDeserialize,
{
    pub client_merkle_tree_root: ClientMerkleTreeRoot<Conf>,
    pub client_signature_public_key: ClientSignatureSchemePublicKey<Conf>,
    pub server_seed: PRFSchemeSeed<Conf>,
}

impl<Conf: Config> GenerateRandomnessSignatureInputExpand<Conf>
where
    ClientSignatureSchemePublicKey<Conf>: CanonicalDeserialize,
{
    /// Create signature input message from the received client message and the server seed.
    pub fn new(
        client_message: GenerateRandomnessMessageClientExpand<Conf>,
        server_seed: PRFSchemeSeed<Conf>,
    ) -> Self {
        Self {
            client_merkle_tree_root: client_message.client_merkle_tree_root,
            client_signature_public_key: client_message.client_signature_public_key,
            server_seed,
        }
    }
}

/// Message sent by the client as part of the `Randomize` step of the paper.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifiableRandomizationMessageExpand<Conf: Config, const INPUT_BYTES: usize>
where
    Proof<Conf>: CanonicalDeserialize,
    ServerSignatureSchemeSignature<Conf>: CanonicalDeserialize,
    ClientSignatureSchemePublicKey<Conf>: CanonicalDeserialize,
{
    pub client_sig_pk: ClientSignatureSchemePublicKey<Conf>,
    pub client_merkle_tree_root: ClientMerkleTreeRoot<Conf>,
    pub server_seed: PRFSchemeSeed<Conf>,
    pub server_signature: ServerSignatureSchemeSignature<Conf>,
    pub proof: Proof<Conf>,
    pub ldp_value: u64,
}
