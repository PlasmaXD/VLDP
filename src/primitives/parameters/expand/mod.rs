//! Convenient struct for using the parameters of the Expand VLDP scheme.

use crate::prelude::*;
use ark_crypto_primitives::crh::CRHScheme;
use astro_float::{BigFloat, Consts, Radix, RoundingMode};
use num_bigint::BigUint;
use std::str::FromStr;

pub mod constraints;
pub use constraints::*;

/// All parameters needed for the shuffle model.
/// Gamma is not directly accessible, as all logic for handling computations involving gamma has
/// been implemented here.
#[derive(Clone)]
pub struct ParametersExpand<Conf: Config, const GAMMA_BYTES: usize> {
    gamma: BigFloat,
    pub client_commitment_scheme: ClientCommitmentSchemeParameters<Conf>,
    pub server_signature_scheme: ServerSignatureSchemeParameters<Conf>,
    pub client_signature_scheme: ClientSignatureSchemeParameters<Conf>,
    pub client_merkle_tree_scheme: ClientMerkleTreeParameters<Conf>,
}

impl<Conf: Config, const GAMMA_BYTES: usize> ParametersExpand<Conf, GAMMA_BYTES> {
    /// Perform the setup of the Expand scheme for the given value of gamma.
    /// This simply generates parameters for all cryptographic primitives.
    pub fn setup<R: Rng + CryptoRng>(gamma: BigFloat, rng: &mut R) -> Result<Self, Error> {
        assert!(BigFloat::from(0) < gamma && gamma <= BigFloat::from(1));
        Ok(Self {
            gamma,
            client_commitment_scheme: Conf::ClientCommitmentScheme::setup(rng)?,
            server_signature_scheme: Conf::ServerSignatureScheme::setup(rng)?,
            client_signature_scheme: Conf::ClientSignatureScheme::setup(rng)?,
            client_merkle_tree_scheme: ClientMerkleTreeParameters::setup(rng)?,
        })
    }

    /// Transform a floating point value of gamma to a byte array in a deterministic way, with
    /// as much precision as possible. This is needed for encoding inside the ZKP circuit.
    pub fn gamma_as_bytes(&self) -> Result<[u8; GAMMA_BYTES], Error> {
        let precision = GAMMA_BYTES * 8 * 2;
        let mut gamma = self.gamma.clone();
        gamma.set_precision(precision, RoundingMode::Down)?;
        let gamma_as_int = gamma
            .mul_full_prec(
                &BigFloat::from_u8(2, precision)
                    .powi(GAMMA_BYTES * 8, precision, RoundingMode::Down)
                    .sub_full_prec(&BigFloat::from_u8(1, precision)),
            )
            .int();
        let gamma_as_str = gamma_as_int
            .convert_to_radix(
                Radix::Dec,
                RoundingMode::None,
                &mut Consts::new().expect("Constants cache initialization should not fail."),
            )?
            .1
            .iter()
            .map(|digit| digit.to_string())
            .collect::<String>();
        let mut bytes = [0; GAMMA_BYTES];
        bytes.copy_from_slice(&BigUint::from_str(&gamma_as_str)?.to_bytes_le());
        Ok(bytes)
    }
}

/// Convenient struct for storing the hash parameters of the hash functions inside the Merkle tree:
/// - `leaf_crh_params`: hash function for hashing leaves.
/// - `two_to_one_crh_params`: for hashing two child nodes into a parent node.
#[derive(Clone)]
pub struct ClientMerkleTreeParameters<Conf: Config> {
    pub leaf_crh_params: ClientMerkleTreeLeafHashParameters<Conf>,
    pub two_to_one_crh_params: ClientMerkleTreeTwoToOneHashParameters<Conf>,
}

impl<Conf: Config> ClientMerkleTreeParameters<Conf> {
    /// Generate new parameters for the Merkle tree.
    pub fn setup<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self, Error> {
        Ok(Self {
            leaf_crh_params: <ClientMerkleTreeLeafHash<Conf> as CRHScheme>::setup(rng)?,
            two_to_one_crh_params:
                <ClientMerkleTreeTwoToOneHash<Conf> as TwoToOneCRHScheme>::setup(rng)?,
        })
    }
}
