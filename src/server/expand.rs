//! All functionalities for a server in the Expand scheme

use crate::circuits::CircuitExpand;
use crate::messages::expand::*;
use crate::prelude::*;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Expand scheme server
pub struct ServerExpand<
    Conf: Config,
    const MT_DEPTH: usize,
    const INPUT_BYTES: usize,
    const TIME_BYTES: usize,
    const GAMMA_BYTES: usize,
    const RANDOMNESS_BYTES: usize,
    const K: u64,
    const IS_REAL_INPUT: bool,
> {
    parameters: ParametersExpand<Conf, GAMMA_BYTES>,
    sig_pk: ServerSignatureSchemePublicKey<Conf>,
    sig_sk: ServerSignatureSchemeSecretKey<Conf>,
    verifying_key: VerifyingKey<Conf>,
}

impl<
        Conf: Config,
        const MT_DEPTH: usize,
        const INPUT_BYTES: usize,
        const TIME_BYTES: usize,
        const GAMMA_BYTES: usize,
        const RANDOMNESS_BYTES: usize,
        const K: u64,
        const IS_REAL_INPUT: bool,
    >
    ServerExpand<
        Conf,
        MT_DEPTH,
        INPUT_BYTES,
        TIME_BYTES,
        GAMMA_BYTES,
        RANDOMNESS_BYTES,
        K,
        IS_REAL_INPUT,
    >
{
    /// Create a new server with the given system parameters and proof verification key.
    pub fn new<R: Rng + CryptoRng>(
        parameters: ParametersExpand<Conf, GAMMA_BYTES>,
        verifying_key: VerifyingKey<Conf>,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let (sig_pk, sig_sk) =
            Conf::ServerSignatureScheme::keygen(&parameters.server_signature_scheme, rng)?;
        Ok(Self {
            parameters,
            sig_pk,
            sig_sk,
            verifying_key,
        })
    }

    /// Get server's signature public key
    pub fn get_signature_public_key(&self) -> ServerSignatureSchemePublicKey<Conf> {
        self.sig_pk.clone()
    }

    /// Given a client message perform the `Generate Randomness` step for the server.
    pub fn generate_randomness_create<R: Rng + CryptoRng>(
        &self,
        client_message: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error>
    where
        ClientSignatureSchemePublicKey<Conf>: CanonicalDeserialize,
        ServerSignatureSchemeSignature<Conf>: CanonicalDeserialize,
    {
        // deserialize client message
        let client_message =
            GenerateRandomnessMessageClientExpand::<Conf>::deserialize_compressed(client_message)?;

        // compute server seed
        let mut server_seed = PRFSchemeSeed::<Conf>::default();
        rng.fill_bytes(&mut server_seed);

        // create signature input
        let signature_input =
            GenerateRandomnessSignatureInputExpand::new(client_message, server_seed.clone());
        let mut signature_input_bytes = Vec::new();
        signature_input.serialize_uncompressed(&mut signature_input_bytes)?;

        // sign
        let server_signature = Conf::ServerSignatureScheme::sign(
            &self.parameters.server_signature_scheme,
            &self.sig_sk,
            &signature_input_bytes,
            rng,
        )?;

        // return message
        let mut serialized_message = vec![];
        GenerateRandomnessMessageServerExpand::<Conf> {
            server_seed,
            server_signature,
        }
        .serialize_compressed(&mut serialized_message)?;
        Ok(serialized_message)
    }

    /// Given a client message, current time (step) bounds, list of `prf_eval_points` (s in the
    /// paper) and current `index` (j in the paper) perform the `Verify` step for the server.
    ///
    /// The `skip_proof` flag can be set to `true` to do a faster test run of this function that
    /// skips proof verification.
    /// Note: in actual usage this should be set to `false`.
    pub fn verifiable_randomization_verify<ConfG: ConfigGadget<Conf>>(
        &self,
        client_message: &[u8],
        time_bounds: ([u8; TIME_BYTES], [u8; TIME_BYTES]),
        prf_eval_points: &[PRFSchemeInput<Conf>],
        index: usize,
        zkp_rng: &mut ZKPRng<Conf>,
        skip_proof: bool,
    ) -> Result<(bool, u64), Error>
    where
        ClientSignatureSchemePublicKey<Conf>:
            ToConstraintField<ConstraintField<Conf>> + CanonicalDeserialize,
        ClientMerkleTreeRoot<Conf>: ToConstraintField<ConstraintField<Conf>>,
        Proof<Conf>: CanonicalDeserialize,
        ServerSignatureSchemeSignature<Conf>: CanonicalDeserialize,
    {
        // deserialize client message
        let client_message =
            VerifiableRandomizationMessageExpand::<Conf, INPUT_BYTES>::deserialize_compressed(
                client_message,
            )?;

        // reconstruct signature input
        let signature_input = GenerateRandomnessSignatureInputExpand::<Conf> {
            client_merkle_tree_root: client_message.client_merkle_tree_root.clone(),
            client_signature_public_key: client_message.client_sig_pk.clone(),
            server_seed: client_message.server_seed,
        };
        let mut signature_input_bytes = Vec::new();
        signature_input.serialize_uncompressed(&mut signature_input_bytes)?;

        // first verify signature
        if Conf::ServerSignatureScheme::verify(
            &self.parameters.server_signature_scheme,
            &self.sig_pk,
            &signature_input_bytes,
            &client_message.server_signature,
        )? {
            // reconstruct server randomness
            let mut server_randomness = [0; RANDOMNESS_BYTES];
            for (chunk, prf_eval_point) in server_randomness.chunks_mut(32).zip(prf_eval_points) {
                chunk.copy_from_slice(
                    &Conf::PRFScheme::evaluate(&client_message.server_seed, &prf_eval_point)?
                        [0..chunk.len()],
                );
            }
            // then verify proof
            if skip_proof {
                Ok((true, client_message.ldp_value))
            } else {
                CircuitExpand::<
                    _,
                    ConfG,
                    MT_DEPTH,
                    INPUT_BYTES,
                    TIME_BYTES,
                    GAMMA_BYTES,
                    RANDOMNESS_BYTES,
                    K,
                    IS_REAL_INPUT,
                >::verify(
                    &self.verifying_key,
                    &client_message.proof,
                    client_message.ldp_value,
                    time_bounds,
                    &client_message.client_sig_pk,
                    &client_message.client_merkle_tree_root,
                    index,
                    server_randomness,
                    zkp_rng,
                )
                .map(|x| (x, client_message.ldp_value))
            }
        } else {
            Ok((false, u64::MAX))
        }
    }
}
