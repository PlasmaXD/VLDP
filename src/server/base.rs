//! All functionalities for a server in the Base scheme

use crate::circuits::CircuitBase;
use crate::messages::base::*;
use crate::prelude::*;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Base scheme server
pub struct ServerBase<
    Conf: Config,
    const INPUT_BYTES: usize,
    const TIME_BYTES: usize,
    const GAMMA_BYTES: usize,
    const RANDOMNESS_BYTES: usize,
    const K: u64,
    const IS_REAL_INPUT: bool,
> {
    parameters: ParametersBase<Conf, GAMMA_BYTES>,
    sig_pk: ServerSignatureSchemePublicKey<Conf>,
    sig_sk: ServerSignatureSchemeSecretKey<Conf>,
    verifying_key: VerifyingKey<Conf>,
}

impl<
        Conf: Config,
        const INPUT_BYTES: usize,
        const TIME_BYTES: usize,
        const GAMMA_BYTES: usize,
        const RANDOMNESS_BYTES: usize,
        const K: u64,
        const IS_REAL_INPUT: bool,
    > ServerBase<Conf, INPUT_BYTES, TIME_BYTES, GAMMA_BYTES, RANDOMNESS_BYTES, K, IS_REAL_INPUT>
{
    /// Create a new server with the given system parameters and proof verification key.
    pub fn new<R: Rng + CryptoRng>(
        parameters: ParametersBase<Conf, GAMMA_BYTES>,
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
        ClientCommitmentSchemeOutput<Conf>: CanonicalDeserialize,
        ClientSignatureSchemePublicKey<Conf>: CanonicalDeserialize,
        ServerSignatureSchemeSignature<Conf>: CanonicalDeserialize,
    {
        // deserialize client message
        let client_message =
            GenerateRandomnessMessageClientBase::<Conf, TIME_BYTES>::deserialize_compressed(
                client_message,
            )?;

        // compute server seed
        let mut server_seed = PRFSchemeSeed::<Conf>::default();
        rng.fill_bytes(&mut server_seed);

        // create signature input
        let signature_input =
            GenerateRandomnessSignatureInputBase::new(client_message, server_seed.clone());
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
        GenerateRandomnessMessageServerBase::<Conf> {
            server_seed,
            server_signature,
        }
        .serialize_compressed(&mut serialized_message)?;
        Ok(serialized_message)
    }

    /// Given a client message perform the `Verify` step for the server.
    pub fn verifiable_randomization_verify<ConfG: ConfigGadget<Conf>>(
        &self,
        client_message: &[u8],
        time_bounds: ([u8; TIME_BYTES], [u8; TIME_BYTES]),
        zkp_rng: &mut ZKPRng<Conf>,
        skip_proof: bool,
    ) -> Result<(bool, u64), Error>
    where
        ClientSignatureSchemePublicKey<Conf>:
            ToConstraintField<ConstraintField<Conf>> + CanonicalDeserialize,
        ClientCommitmentSchemeOutput<Conf>:
            ToConstraintField<ConstraintField<Conf>> + CanonicalDeserialize,
        Proof<Conf>: CanonicalDeserialize,
        ServerSignatureSchemeSignature<Conf>: CanonicalDeserialize,
    {
        // deserialize client message
        let client_message =
            VerifiableRandomizationMessageBase::<Conf, INPUT_BYTES>::deserialize_compressed(
                client_message,
            )?;

        // reconstruct signature input
        let signature_input = GenerateRandomnessSignatureInputBase::<Conf> {
            client_randomness_commitment: client_message.client_randomness_commitment.clone(),
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
            for (index, chunk) in server_randomness.chunks_mut(32).enumerate() {
                let mut eval_point = [0; 32];
                for (new_byte, old_byte) in
                    index.to_le_bytes().into_iter().zip(eval_point.iter_mut())
                {
                    *old_byte = new_byte;
                }
                chunk.copy_from_slice(
                    &Conf::PRFScheme::evaluate(&client_message.server_seed, &eval_point)?
                        [0..chunk.len()],
                );
            }
            // then verify proof
            if skip_proof {
                Ok((true, client_message.ldp_value))
            } else {
                CircuitBase::<
                    _,
                    ConfG,
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
                    client_message.client_randomness_commitment,
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
