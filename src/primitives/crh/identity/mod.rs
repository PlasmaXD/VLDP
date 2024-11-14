use crate::prelude::*;
use ark_crypto_primitives::crh::CRHScheme;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::borrow::Borrow;
use std::fmt::Debug;
use std::hash::Hash;
use std::marker::PhantomData;

pub mod constraints;

#[derive(Clone)]
pub struct IdentityHash<T> {
    #[doc(hidden)]
    _type: PhantomData<T>,
}

impl<T> CRHScheme for IdentityHash<T>
where
    T: Clone + Eq + Debug + Hash + Default + CanonicalSerialize + CanonicalDeserialize,
{
    type Input = T;
    type Output = T;
    type Parameters = ();

    fn setup<R: Rng>(_: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate<Input: Borrow<Self::Input>>(
        _: &Self::Parameters,
        input: Input,
    ) -> Result<Self::Output, Error> {
        Ok(input.borrow().clone())
    }
}
