//! This describes the configuration that was used for the Merkle Tree in the Expand protocol for
//! our experiments in the paper.
//!
//! Different configurations can be made (e.g., changing primitives) by adapting this configuration.
//! Additional implementation of other primitives may be required to support certain other
//! configurations.

use crate::prelude::{constraints::*, *};
use crate::primitives::crh::identity::constraints::IdentityHashGadget;
use crate::primitives::crh::IdentityHash;
use ark_crypto_primitives::crh;
use ark_crypto_primitives::crh::pedersen::Window;
use ark_crypto_primitives::crh::{
    CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget,
};
use ark_crypto_primitives::merkle_tree::constraints::BytesVarDigestConverter;
use ark_crypto_primitives::merkle_tree::ByteDigestConverter;
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::fmt::Debug;
use std::hash::Hash;
use std::marker::PhantomData;

/// Basic configuration struct as used for the experiments in the paper.
#[derive(Clone)]
pub struct PedersenMerkleTreeConfig<C: CurveGroup, Input, TwoToOneW: Window> {
    #[doc(hidden)]
    _curve_group: PhantomData<C>,

    #[doc(hidden)]
    _input: PhantomData<Input>,

    #[doc(hidden)]
    _two_to_one_windows: PhantomData<TwoToOneW>,
}

// HERE IS THE ACTUAL DEFINITION OF THE USED PRIMITIVES
impl<C: CurveGroup, Input, TwoToOneW: Window> ark_crypto_primitives::merkle_tree::Config
    for PedersenMerkleTreeConfig<C, Input, TwoToOneW>
where
    Input: Clone + Eq + Debug + Hash + Default + CanonicalSerialize + CanonicalDeserialize,
{
    type Leaf = <Self::LeafHash as CRHScheme>::Input;
    type LeafDigest = <Self::LeafHash as CRHScheme>::Output;
    type LeafInnerDigestConverter = ByteDigestConverter<Self::LeafDigest>;
    type InnerDigest = <Self::TwoToOneHash as TwoToOneCRHScheme>::Output;
    type LeafHash = IdentityHash<Input>;
    type TwoToOneHash = crh::pedersen::TwoToOneCRH<C, TwoToOneW>;
}

/// Basic configuration struct for the R1CS part of the configuration as used for the experiments
/// in the paper.
#[derive(Clone)]
pub struct PedersenMerkleTreeConfigGadget<C: CurveGroup, CG: CurveVar<C, ConstraintF<C>>, InputG>
where
    for<'a> &'a CG: GroupOpsBounds<'a, C, CG>,
{
    #[doc(hidden)]
    _group: PhantomData<C>,

    #[doc(hidden)]
    _group_var: PhantomData<CG>,

    #[doc(hidden)]
    _input_var: PhantomData<InputG>,
}

// HERE IS THE ACTUAL DEFINITION OF THE USED GADGETS
impl<C: CurveGroup, CG: CurveVar<C, ConstraintF<C>>, Input, InputG, TwoToOneW: Window>
    ark_crypto_primitives::merkle_tree::constraints::ConfigGadget<
        PedersenMerkleTreeConfig<C, Input, TwoToOneW>,
        ConstraintF<C>,
    > for PedersenMerkleTreeConfigGadget<C, CG, InputG>
where
    Input: Clone + Eq + Debug + Hash + Default + CanonicalSerialize + CanonicalDeserialize,
    InputG: EqGadget<ConstraintF<C>>
        + ToBytesGadget<ConstraintF<C>>
        + CondSelectGadget<ConstraintF<C>>
        + AllocVar<Input, ConstraintF<C>>
        + R1CSVar<ConstraintF<C>>
        + Debug,
    for<'a> &'a CG: GroupOpsBounds<'a, C, CG>,
{
    type Leaf = <Self::LeafHash as CRHSchemeGadget<
        <PedersenMerkleTreeConfig<C, Input, TwoToOneW> as ark_crypto_primitives::merkle_tree::Config>::LeafHash,
        ConstraintF<C>,
    >>::InputVar;
    type LeafDigest = <Self::LeafHash as CRHSchemeGadget<
        <PedersenMerkleTreeConfig<C, Input, TwoToOneW> as ark_crypto_primitives::merkle_tree::Config>::LeafHash,
        ConstraintF<C>,
    >>::OutputVar;
    type LeafInnerConverter = BytesVarDigestConverter<Self::LeafDigest, ConstraintF<C>>;
    type InnerDigest = <Self::TwoToOneHash as TwoToOneCRHSchemeGadget<
        <PedersenMerkleTreeConfig<C, Input, TwoToOneW> as ark_crypto_primitives::merkle_tree::Config>::TwoToOneHash,
        ConstraintF<C>,
    >>::OutputVar;
    type LeafHash = IdentityHashGadget<InputG>;
    type TwoToOneHash = crh::pedersen::constraints::TwoToOneCRHGadget<C, CG, TwoToOneW>;
}
