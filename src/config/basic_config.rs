//! This describes the configuration that was used for the experiments in the paper.
//!
//! Different configurations can be made (e.g., changing primitives) by adapting this configuration.
//! Additional implementation of other primitives may be required to support certain other
//! configurations.

use super::windows::{ClientCommitmentSchemeWindow, PedersenMerkleTreeWindow};
use crate::config::merkle_tree::{PedersenMerkleTreeConfig, PedersenMerkleTreeConfigGadget};
use crate::prelude::{constraints::*, *};
use crate::primitives::crh;
use crate::primitives::signature::schnorr::constraints::SchnorrSignatureVerifyGadget;
use crate::primitives::signature::Schnorr;
use ark_crypto_primitives::commitment::pedersen::constraints::CommGadget;
use ark_crypto_primitives::commitment::pedersen::Commitment;
use ark_crypto_primitives::prf;
use ark_ec::CurveGroup;
use std::marker::PhantomData;

/// Basic configuration struct as used for the experiments in the paper.
pub struct BasicConfig<
    C: CurveGroup,
    R: ProofSystemRng,
    PS: ProofSystem<R, ConstraintField = ConstraintF<C>>,
    const NUM_COMM_BYTES: usize,
> {
    /// Needed to bind these generic types to the struct.
    #[doc(hidden)]
    _curve_group: PhantomData<C>,
    #[doc(hidden)]
    _rng: PhantomData<R>,
    #[doc(hidden)]
    _proof_system: PhantomData<PS>,
}

// We need to manually implement clone due to the const generic.
impl<
        C: CurveGroup,
        R: ProofSystemRng,
        PS: ProofSystem<R, ConstraintField = ConstraintF<C>>,
        const NUM_COMM_BYTES: usize,
    > Clone for BasicConfig<C, R, PS, NUM_COMM_BYTES>
{
    fn clone(&self) -> Self {
        Self {
            _curve_group: PhantomData,
            _rng: PhantomData,
            _proof_system: PhantomData,
        }
    }
}

// HERE IS THE ACTUAL DEFINITION OF THE USED PRIMITIVES
impl<
        C: CurveGroup,
        R: ProofSystemRng,
        PS: ProofSystem<R, ConstraintField = ConstraintF<C>>,
        const NUM_COMM_BYTES: usize,
    > Config for BasicConfig<C, R, PS, NUM_COMM_BYTES>
{
    type ZKPRng = R;
    type ZKPScheme = PS;
    type ClientCommitmentScheme = Commitment<C, ClientCommitmentSchemeWindow<NUM_COMM_BYTES>>;
    type ServerSignatureScheme = Schnorr<C, crh::Blake2s256>;
    type PRFScheme = prf::Blake2s;
    type ClientSignatureScheme = Schnorr<C, crh::Blake2s256>;
    type ClientMerkleTreeConfig =
        PedersenMerkleTreeConfig<C, ClientCommitmentSchemeOutput<Self>, PedersenMerkleTreeWindow>;
}

/// Basic configuration struct for the R1CS part of the configuration as used for the experiments
/// in the paper.
#[derive(Clone)]
pub struct BasicConfigGadget<C: CurveGroup, CG: CurveVar<C, ConstraintF<C>>> {
    #[doc(hidden)]
    _curve_group: PhantomData<C>,
    _curve_group_gadget: PhantomData<CG>,
}

// HERE IS THE ACTUAL DEFINITION OF THE USED GADGETS
impl<
        C: CurveGroup,
        R: ProofSystemRng,
        PS: ProofSystem<R, ConstraintField = ConstraintF<C>>,
        CG: CurveVar<C, ConstraintF<C>>,
        const NUM_COMM_BYTES: usize,
    > ConfigGadget<BasicConfig<C, R, PS, NUM_COMM_BYTES>> for BasicConfigGadget<C, CG>
where
    for<'a> &'a CG: GroupOpsBounds<'a, C, CG>,
{
    type ClientCommitmentVerifyGadget =
        CommGadget<C, CG, ClientCommitmentSchemeWindow<NUM_COMM_BYTES>>;
    type ServerSignatureVerifyGadget = SchnorrSignatureVerifyGadget<
        C,
        CG,
        crh::Blake2s256,
        crh::blake2s::constraints::Blake2s256Gadget,
    >;
    type PRFVerifyGadget = prf::blake2s::constraints::Blake2sGadget;
    type ClientSignatureVerifyGadget = SchnorrSignatureVerifyGadget<
        C,
        CG,
        crh::Blake2s256,
        crh::blake2s::constraints::Blake2s256Gadget,
    >;
    type ClientMerkleTreeConfigGadget = PedersenMerkleTreeConfigGadget<
        C,
        CG,
        ClientCommitmentSchemeOutputVar<BasicConfig<C, R, PS, NUM_COMM_BYTES>, Self>,
    >;
}
