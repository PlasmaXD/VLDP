//! Convenient traits/structs to store all configuration options (e.g., ZKP scheme to use,
//! commitment scheme to use, PRF to use, ...) of a VLDP scheme.

pub mod basic_config;
pub use basic_config::*;

pub mod proof_system;
pub use proof_system::*;

mod merkle_tree;
mod windows;

use crate::prelude::{constraints::*, *};

/// Trait that describes all configuration options that are to be defined in a configuration struct.
pub trait Config: Clone {
    type ZKPRng: ProofSystemRng;
    type ZKPScheme: ProofSystem<Self::ZKPRng>;
    type ClientCommitmentScheme: CommitmentScheme;
    type ServerSignatureScheme: SignatureScheme;
    type PRFScheme: PRF<Input = [u8; 32], Seed = [u8; 32], Output = [u8; 32]>;
    type ClientSignatureScheme: SignatureScheme;
    type ClientMerkleTreeConfig: ark_crypto_primitives::merkle_tree::Config<
        Leaf = ClientCommitmentSchemeOutput<Self>,
    >;
}

/// Subtrait of the `Config` trait to additionally describe all options that are to be defined
/// in a configuration struct regarding the ZKP generation.
/// Basically, this includes all accompanying ZKP circuit-related types to the `Config` struct.
pub trait ConfigGadget<Conf: Config>: Clone {
    type ClientCommitmentVerifyGadget: CommitmentGadget<
        Conf::ClientCommitmentScheme,
        ConstraintField<Conf>,
    >;
    type ServerSignatureVerifyGadget: SigVerifyGadget<
        Conf::ServerSignatureScheme,
        ConstraintField<Conf>,
    >;
    type PRFVerifyGadget: PRFGadget<Conf::PRFScheme, ConstraintField<Conf>>;
    type ClientSignatureVerifyGadget: SigVerifyGadget<
        Conf::ClientSignatureScheme,
        ConstraintField<Conf>,
    >;
    type ClientMerkleTreeConfigGadget: ark_crypto_primitives::merkle_tree::constraints::ConfigGadget<
        Conf::ClientMerkleTreeConfig,
        ConstraintField<Conf>,
        Leaf = ClientCommitmentSchemeOutputVar<Conf, Self>,
    >;
}
