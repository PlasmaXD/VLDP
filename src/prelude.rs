//! Convenient re-exports and aliases that we often need in this crate

use ark_crypto_primitives::merkle_tree;
use ark_ec::CurveGroup;

// convenient re-exports
pub use crate::config::{Config, ConfigGadget, ProofSystem, ProofSystemRng};
pub use crate::error::*;
pub use crate::primitives::parameters::{ParametersBase, ParametersExpand, ParametersShuffle};
pub use crate::primitives::signature::SignatureScheme;
pub use ark_crypto_primitives::commitment::CommitmentScheme;
pub use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
pub use ark_crypto_primitives::merkle_tree::{MerkleTree, Path};
pub use ark_crypto_primitives::prf::PRF;
pub use ark_ec::pairing::Pairing;
pub use ark_ff::Field;
pub use ark_ff::ToConstraintField;
pub use ark_std::UniformRand;
pub use rand::prelude::{CryptoRng, Rng};

// convenient aliases
// generic
pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;
pub type Error = Box<dyn std::error::Error>;
// zkp scheme
pub type ZKPRng<Conf> = <Conf as Config>::ZKPRng;
pub type ConstraintField<Conf> =
    <<Conf as Config>::ZKPScheme as ProofSystem<<Conf as Config>::ZKPRng>>::ConstraintField;
pub type Proof<Conf> =
    <<Conf as Config>::ZKPScheme as ProofSystem<<Conf as Config>::ZKPRng>>::Proof;
pub type ProvingKey<Conf> =
    <<Conf as Config>::ZKPScheme as ProofSystem<<Conf as Config>::ZKPRng>>::ProvingKey;
pub type VerifyingKey<Conf> =
    <<Conf as Config>::ZKPScheme as ProofSystem<<Conf as Config>::ZKPRng>>::VerifyingKey;
// client commitment scheme
pub type ClientCommitmentSchemeParameters<Conf> =
    <<Conf as Config>::ClientCommitmentScheme as CommitmentScheme>::Parameters;
pub type ClientCommitmentSchemeOutput<Conf> =
    <<Conf as Config>::ClientCommitmentScheme as CommitmentScheme>::Output;
pub type ClientCommitmentSchemeRandomness<Conf> =
    <<Conf as Config>::ClientCommitmentScheme as CommitmentScheme>::Randomness;
// server signature scheme
pub type ServerSignatureSchemeParameters<Conf> =
    <<Conf as Config>::ServerSignatureScheme as SignatureScheme>::Parameters;
pub type ServerSignatureSchemePublicKey<Conf> =
    <<Conf as Config>::ServerSignatureScheme as SignatureScheme>::PublicKey;
pub type ServerSignatureSchemeSecretKey<Conf> =
    <<Conf as Config>::ServerSignatureScheme as SignatureScheme>::SecretKey;
pub type ServerSignatureSchemeSignature<Conf> =
    <<Conf as Config>::ServerSignatureScheme as SignatureScheme>::Signature;
// client PRF
pub type PRFSchemeInput<Conf> = <<Conf as Config>::PRFScheme as PRF>::Input;
pub type PRFSchemeSeed<Conf> = <<Conf as Config>::PRFScheme as PRF>::Seed;
// client signature scheme
pub type ClientSignatureSchemeParameters<Conf> =
    <<Conf as Config>::ClientSignatureScheme as SignatureScheme>::Parameters;
pub type ClientSignatureSchemePublicKey<Conf> =
    <<Conf as Config>::ClientSignatureScheme as SignatureScheme>::PublicKey;
pub type ClientSignatureSchemeSecretKey<Conf> =
    <<Conf as Config>::ClientSignatureScheme as SignatureScheme>::SecretKey;
pub type ClientSignatureSchemeSignature<Conf> =
    <<Conf as Config>::ClientSignatureScheme as SignatureScheme>::Signature;
// client merkle tree
pub type ClientMerkleTreeConfig<Conf> = <Conf as Config>::ClientMerkleTreeConfig;
pub type ClientMerkleTree<Conf> = MerkleTree<ClientMerkleTreeConfig<Conf>>;
pub type ClientMerkleTreeLeafHash<Conf> =
    <ClientMerkleTreeConfig<Conf> as merkle_tree::Config>::LeafHash;
pub type ClientMerkleTreeLeafHashParameters<Conf> =
    <ClientMerkleTreeLeafHash<Conf> as CRHScheme>::Parameters;
pub type ClientMerkleTreeTwoToOneHash<Conf> =
    <ClientMerkleTreeConfig<Conf> as merkle_tree::Config>::TwoToOneHash;
pub type ClientMerkleTreeTwoToOneHashParameters<Conf> =
    <ClientMerkleTreeTwoToOneHash<Conf> as TwoToOneCRHScheme>::Parameters;
pub type ClientMerkleTreeRoot<Conf> =
    <ClientMerkleTreeConfig<Conf> as merkle_tree::Config>::InnerDigest;
pub type ClientMerkleTreePath<Conf> = Path<ClientMerkleTreeConfig<Conf>>;

pub(crate) mod constraints {
    use super::*;
    // convenient re-exports
    pub use crate::primitives::parameters::{
        ParametersBaseVar, ParametersExpandVar, ParametersShuffleVar,
    };
    pub use crate::primitives::signature::SigVerifyGadget;
    pub use ark_crypto_primitives::commitment::CommitmentGadget;
    pub use ark_crypto_primitives::crh::{CRHSchemeGadget, TwoToOneCRHSchemeGadget};
    pub use ark_crypto_primitives::merkle_tree::constraints::PathVar;
    pub use ark_crypto_primitives::prf::PRFGadget;
    pub use ark_r1cs_std::prelude::*;

    // client commitment scheme
    pub type ClientCommitmentSchemeParametersVar<Conf, ConfG> =
        <<ConfG as ConfigGadget<Conf>>::ClientCommitmentVerifyGadget as CommitmentGadget<
            <Conf as Config>::ClientCommitmentScheme,
            ConstraintField<Conf>,
        >>::ParametersVar;
    pub type ClientCommitmentSchemeRandomnessVar<Conf, ConfG> =
        <<ConfG as ConfigGadget<Conf>>::ClientCommitmentVerifyGadget as CommitmentGadget<
            <Conf as Config>::ClientCommitmentScheme,
            ConstraintField<Conf>,
        >>::RandomnessVar;
    pub type ClientCommitmentSchemeOutputVar<Conf, ConfG> =
        <<ConfG as ConfigGadget<Conf>>::ClientCommitmentVerifyGadget as CommitmentGadget<
            <Conf as Config>::ClientCommitmentScheme,
            ConstraintField<Conf>,
        >>::OutputVar;
    // server signature scheme
    pub type ServerSignatureSchemeParametersVar<Conf, ConfG> =
        <<ConfG as ConfigGadget<Conf>>::ServerSignatureVerifyGadget as SigVerifyGadget<
            <Conf as Config>::ServerSignatureScheme,
            ConstraintField<Conf>,
        >>::ParametersVar;
    pub type ServerSignatureSchemePublicKeyVar<Conf, ConfG> =
        <<ConfG as ConfigGadget<Conf>>::ServerSignatureVerifyGadget as SigVerifyGadget<
            <Conf as Config>::ServerSignatureScheme,
            ConstraintField<Conf>,
        >>::PublicKeyVar;
    pub type ServerSignatureSchemeSignatureVar<Conf, ConfG> =
        <<ConfG as ConfigGadget<Conf>>::ServerSignatureVerifyGadget as SigVerifyGadget<
            <Conf as Config>::ServerSignatureScheme,
            ConstraintField<Conf>,
        >>::SignatureVar;
    // client signature scheme
    pub type ClientSignatureSchemeParametersVar<Conf, ConfG> =
        <<ConfG as ConfigGadget<Conf>>::ClientSignatureVerifyGadget as SigVerifyGadget<
            <Conf as Config>::ClientSignatureScheme,
            ConstraintField<Conf>,
        >>::ParametersVar;
    pub type ClientSignatureSchemePublicKeyVar<Conf, ConfG> =
        <<ConfG as ConfigGadget<Conf>>::ClientSignatureVerifyGadget as SigVerifyGadget<
            <Conf as Config>::ClientSignatureScheme,
            ConstraintField<Conf>,
        >>::PublicKeyVar;
    pub type ClientSignatureSchemeSignatureVar<Conf, ConfG> =
        <<ConfG as ConfigGadget<Conf>>::ClientSignatureVerifyGadget as SigVerifyGadget<
            <Conf as Config>::ClientSignatureScheme,
            ConstraintField<Conf>,
        >>::SignatureVar;
    // client merkle tree
    pub type ClientMerkleTreeConfigGadget<Conf, ConfG> =
        <ConfG as ConfigGadget<Conf>>::ClientMerkleTreeConfigGadget;
    pub type ClientMerkleTreeLeafHashGadget<Conf, ConfG> =
        <ClientMerkleTreeConfigGadget<Conf, ConfG> as merkle_tree::constraints::ConfigGadget<
            ClientMerkleTreeConfig<Conf>,
            ConstraintField<Conf>,
        >>::LeafHash;
    pub type ClientMerkleTreeLeafHashParametersVar<Conf, ConfG> =
        <ClientMerkleTreeLeafHashGadget<Conf, ConfG> as CRHSchemeGadget<
            ClientMerkleTreeLeafHash<Conf>,
            ConstraintField<Conf>,
        >>::ParametersVar;
    pub type ClientMerkleTreeTwoToOneHashGadget<Conf, ConfG> =
        <ClientMerkleTreeConfigGadget<Conf, ConfG> as merkle_tree::constraints::ConfigGadget<
            ClientMerkleTreeConfig<Conf>,
            ConstraintField<Conf>,
        >>::TwoToOneHash;
    pub type ClientMerkleTreeTwoToOneHashParametersVar<Conf, ConfG> =
        <ClientMerkleTreeTwoToOneHashGadget<Conf, ConfG> as TwoToOneCRHSchemeGadget<
            ClientMerkleTreeTwoToOneHash<Conf>,
            ConstraintField<Conf>,
        >>::ParametersVar;
    pub type ClientMerkleTreeRootVar<Conf, ConfG> =
        <ClientMerkleTreeConfigGadget<Conf, ConfG> as merkle_tree::constraints::ConfigGadget<
            ClientMerkleTreeConfig<Conf>,
            ConstraintField<Conf>,
        >>::InnerDigest;
    pub type ClientMerkleTreePathVar<Conf, ConfG> = PathVar<
        ClientMerkleTreeConfig<Conf>,
        ConstraintField<Conf>,
        ClientMerkleTreeConfigGadget<Conf, ConfG>,
    >;
}
// --- end CONVENIENT ALIASES ---
