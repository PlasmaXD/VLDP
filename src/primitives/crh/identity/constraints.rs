use crate::prelude::*;
use crate::primitives::crh::IdentityHash;
use ark_crypto_primitives::crh::CRHSchemeGadget;
use ark_ff::PrimeField;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::borrow::Borrow;
use std::fmt::Debug;
use std::hash::Hash;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct ParametersVar;

#[derive(Clone)]
pub struct IdentityHashGadget<TG> {
    #[doc(hidden)]
    _type_gadget: PhantomData<TG>,
}

impl<ConstraintF: PrimeField, T, TG> CRHSchemeGadget<IdentityHash<T>, ConstraintF>
    for IdentityHashGadget<TG>
where
    T: Clone + Eq + Debug + Hash + Default + CanonicalSerialize + CanonicalDeserialize,
    TG: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + CondSelectGadget<ConstraintF>
        + AllocVar<T, ConstraintF>
        + R1CSVar<ConstraintF>
        + Debug,
{
    type InputVar = TG;
    type OutputVar = TG;
    type ParametersVar = ParametersVar;

    fn evaluate(
        _: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        Ok(input.clone())
    }
}

impl<ConstraintF: Field> AllocVar<(), ConstraintF> for ParametersVar {
    fn new_variable<T: Borrow<()>>(
        _cs: impl Into<Namespace<ConstraintF>>,
        _f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        Ok(ParametersVar)
    }
}
