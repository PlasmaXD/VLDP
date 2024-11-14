//! All functionalities for a client in the Expand scheme

use crate::circuits::CircuitShuffle;
use crate::messages::shuffle::*;
use crate::prelude::*;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::Zero;
use num_bigint::BigUint;
use std::cmp::min;

/// Storage of values between steps for a client in the Shuffle scheme
#[derive(Clone)]
pub struct ClientShuffleStorage<Conf: Config> {
    pub client_seed: Option<PRFSchemeSeed<Conf>>,
    pub client_seed_commitment_randomness: Option<ClientCommitmentSchemeRandomness<Conf>>,
    pub client_seed_commitment: Option<ClientCommitmentSchemeOutput<Conf>>,
    pub server_seed: Option<PRFSchemeSeed<Conf>>,
    pub server_signature: Option<ServerSignatureSchemeSignature<Conf>>,
}

impl<Conf: Config> ClientShuffleStorage<Conf> {
    /// Construct an empty client storage
    pub fn new() -> Self {
        Self {
            client_seed: None,
            client_seed_commitment_randomness: None,
            client_seed_commitment: None,
            server_seed: None,
            server_signature: None,
        }
    }
}

/// Shuffle scheme client
pub struct ClientShuffle<
    Conf: Config,
    const INPUT_BYTES: usize,
    const TIME_BYTES: usize,
    const GAMMA_BYTES: usize,
    const RANDOMNESS_BYTES: usize,
    const K: u64,
    const IS_REAL_INPUT: bool,
> {
    parameters: ParametersShuffle<Conf, GAMMA_BYTES>,
    server_sig_pk: ServerSignatureSchemePublicKey<Conf>,
    client_sig_pk: ClientSignatureSchemePublicKey<Conf>,
    proving_key: ProvingKey<Conf>,
    storage: ClientShuffleStorage<Conf>,
}

impl<
        Conf: Config,
        const INPUT_BYTES: usize,
        const TIME_BYTES: usize,
        const GAMMA_BYTES: usize,
        const RANDOMNESS_BYTES: usize,
        const K: u64,
        const IS_REAL_INPUT: bool,
    >
    ClientShuffle<Conf, INPUT_BYTES, TIME_BYTES, GAMMA_BYTES, RANDOMNESS_BYTES, K, IS_REAL_INPUT>
{
    /// Create a new client with the given system parameters, signature public keys (server and client) and proof generation key.
    pub fn new(
        parameters: ParametersShuffle<Conf, GAMMA_BYTES>,
        server_sig_pk: ServerSignatureSchemePublicKey<Conf>,
        client_sig_pk: ClientSignatureSchemePublicKey<Conf>,
        proving_key: ProvingKey<Conf>,
    ) -> Result<Self, Error> {
        Ok(Self {
            parameters,
            server_sig_pk,
            client_sig_pk,
            proving_key,
            storage: ClientShuffleStorage::new(),
        })
    }

    /// Perform the first part of the `Generate Randomness` step of the client.
    pub fn generate_randomness_create<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error>
    where
        ClientCommitmentSchemeOutput<Conf>: CanonicalDeserialize,
        ClientSignatureSchemePublicKey<Conf>: CanonicalDeserialize,
    {
        let mut client_seed = PRFSchemeSeed::<Conf>::default();
        rng.fill_bytes(&mut client_seed);
        let commitment_randomness = ClientCommitmentSchemeRandomness::<Conf>::rand(rng);
        let client_seed_commitment = Conf::ClientCommitmentScheme::commit(
            &self.parameters.client_commitment_scheme,
            &client_seed,
            &commitment_randomness,
        )?;

        // storage
        self.storage.client_seed = Some(client_seed);
        self.storage.client_seed_commitment_randomness = Some(commitment_randomness);
        self.storage.client_seed_commitment = Some(client_seed_commitment.clone());

        // return message
        let mut serialized_message = vec![];
        GenerateRandomnessMessageClientShuffle::<Conf> {
            client_seed_commitment,
            client_signature_public_key: self.client_sig_pk.clone(),
        }
        .serialize_compressed(&mut serialized_message)?;
        Ok(serialized_message)
    }

    /// Perform the second part of the `Generate Randomness` step of the client.
    pub fn generate_randomness_verify(&mut self, server_message: &[u8]) -> Result<bool, Error>
    where
        ClientSignatureSchemePublicKey<Conf>: CanonicalDeserialize,
        ClientCommitmentSchemeOutput<Conf>: CanonicalDeserialize,
        ServerSignatureSchemeSignature<Conf>: CanonicalDeserialize,
    {
        // deserialize server message
        let server_message =
            GenerateRandomnessMessageServerShuffle::<Conf>::deserialize_compressed(server_message)?;

        // reconstruct signature input
        let signature_input = GenerateRandomnessSignatureInputShuffle::<Conf> {
            client_seed_commitment: self
                .storage
                .client_seed_commitment
                .clone()
                .ok_or(ClientError::UnobtainedValue)?,
            client_signature_public_key: self.client_sig_pk.clone(),
            server_seed: server_message.server_seed.clone(),
        };
        let mut signature_input_bytes = Vec::new();
        signature_input.serialize_uncompressed(&mut signature_input_bytes)?;

        // verify signature
        if Conf::ServerSignatureScheme::verify(
            &self.parameters.server_signature_scheme,
            &self.server_sig_pk,
            &signature_input_bytes,
            &server_message.server_signature,
        )? {
            // storage
            self.storage.server_seed = Some(server_message.server_seed);
            self.storage.server_signature = Some(server_message.server_signature);

            // return success
            Ok(true)
        } else {
            // signature verification failed
            Ok(false)
        }
    }

    /// Given the time bounds of the current step, the true input value, the time it was created,
    /// and its signature, along with the list of public `prf_eval_points` (s in the paper) and
    /// current `index` (j in the paper) perform the `Randomize` step of the client.
    ///
    /// The `skip_proof` flag can be set to `true` to do a faster test run of this function that
    /// only executes the randomization (without proof generation).
    /// Note: in actual usage this should be set to `false`.
    pub fn verifiable_randomization_create<ConfG: ConfigGadget<Conf>>(
        &self,
        time_bounds: ([u8; TIME_BYTES], [u8; TIME_BYTES]),
        input_value_time: [u8; TIME_BYTES],
        input_value: BigUint,
        input_value_signature: ClientSignatureSchemeSignature<Conf>,
        prf_eval_points: &[PRFSchemeInput<Conf>],
        zkp_rng: &mut ZKPRng<Conf>,
        skip_proof: bool,
    ) -> Result<Vec<u8>, Error>
    where
        Proof<Conf>: CanonicalDeserialize,
    {
        // compute full seed from client and server part
        let mut seed = self
            .storage
            .client_seed
            .ok_or(ClientError::UnobtainedValue)?;
        seed.iter_mut()
            .zip(
                self.storage
                    .server_seed
                    .ok_or(ClientError::UnobtainedValue)?,
            )
            .for_each(|(client_byte, server_byte)| *client_byte ^= server_byte);

        // compute randomness from seeds
        let mut randomness = [0; RANDOMNESS_BYTES];
        for (chunk, prf_eval_point) in randomness.chunks_mut(32).zip(prf_eval_points) {
            chunk.copy_from_slice(
                &Conf::PRFScheme::evaluate(&seed, &prf_eval_point)?[0..chunk.len()],
            );
        }

        // apply LDP
        let ldp_bit = {
            (BigUint::from_bytes_le(&randomness[0..GAMMA_BYTES])
                <= BigUint::from_bytes_le(&self.parameters.gamma_as_bytes()?)) as u8
        };

        let ldp_value = if ldp_bit == 0 {
            if IS_REAL_INPUT {
                let input_value_times_k = &input_value * K;
                let multiplicand =
                    &input_value_times_k / BigUint::from_bytes_le(&[u8::MAX; INPUT_BYTES]);
                let remainder = &input_value_times_k
                    - &multiplicand * BigUint::from_bytes_le(&[u8::MAX; INPUT_BYTES]);
                let random_input_bytes =
                    &randomness[GAMMA_BYTES + INPUT_BYTES..GAMMA_BYTES + 2 * INPUT_BYTES];
                let random_input_bit =
                    (BigUint::from_bytes_le(&random_input_bytes) <= remainder) as u64;
                if multiplicand.is_zero() {
                    random_input_bit
                } else {
                    multiplicand.to_u64_digits()[0] + random_input_bit
                }
            } else {
                if (&input_value).is_zero() {
                    0
                } else {
                    (&input_value).to_u64_digits()[0]
                }
            }
        } else {
            // ldp_bit == 1
            let boundary_gap = if IS_REAL_INPUT {
                BigUint::from_bytes_le(&[u8::MAX; INPUT_BYTES]) / (K + 1)
            } else {
                BigUint::from_bytes_le(&[u8::MAX; INPUT_BYTES]) / K
            };
            let computed_ldp_value =
                BigUint::from_bytes_le(&randomness[GAMMA_BYTES..GAMMA_BYTES + INPUT_BYTES])
                    / boundary_gap;
            let computed_ldp_value = if computed_ldp_value.is_zero() {
                0
            } else {
                computed_ldp_value.to_u64_digits()[0]
            };
            if IS_REAL_INPUT {
                min(computed_ldp_value, K)
            } else {
                min(computed_ldp_value, K - 1) + 1
            }
        };

        let mut input_value_bytes = [0; INPUT_BYTES];
        for (idx, byte) in input_value.to_bytes_le().iter().enumerate() {
            input_value_bytes[idx] = *byte;
        }

        // create proof
        let proof = if skip_proof {
            Proof::<Conf>::default()
        } else {
            CircuitShuffle::<
                _,
                ConfG,
                INPUT_BYTES,
                TIME_BYTES,
                GAMMA_BYTES,
                RANDOMNESS_BYTES,
                K,
                IS_REAL_INPUT,
            >::prove(
                &self.proving_key,
                self.parameters.clone(),
                ldp_value,
                self.server_sig_pk.clone(),
                prf_eval_points,
                time_bounds,
                input_value_bytes,
                input_value_time,
                input_value_signature,
                self.client_sig_pk.clone(),
                self.storage.clone(),
                zkp_rng,
            )?
        };

        // return message
        let mut serialized_message = vec![];
        VerifiableRandomizationMessageShuffle::<Conf, INPUT_BYTES> { proof, ldp_value }
            .serialize_compressed(&mut serialized_message)?;
        Ok(serialized_message)
    }
}
