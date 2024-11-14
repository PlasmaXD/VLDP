//! R1CS constraint generation and variable allocation for the parameters of the Expand VLDP
//! scheme.

use crate::prelude::{constraints::*, *};
use crate::primitives::parameters::{ClientMerkleTreeParameters, GammaVar};
use ark_relations::r1cs::{Namespace, SynthesisError};
use std::borrow::Borrow;

/// All R1CS variables for the parameters needed for the Expand scheme.
pub struct ParametersExpandVar<Conf: Config, ConfG: ConfigGadget<Conf>> {
    pub gamma: GammaVar<Conf>,
    pub client_commitment_scheme: ClientCommitmentSchemeParametersVar<Conf, ConfG>,
    #[allow(dead_code)]
    pub server_signature_scheme: ServerSignatureSchemeParametersVar<Conf, ConfG>,
    pub client_signature_scheme: ClientSignatureSchemeParametersVar<Conf, ConfG>,
    pub client_merkle_tree_scheme: ClientMerkleTreeParametersVar<Conf, ConfG>,
}

// implement variable allocation of all parameters
impl<Conf: Config, ConfG: ConfigGadget<Conf>, const GAMMA_BYTES: usize>
    AllocVar<ParametersExpand<Conf, GAMMA_BYTES>, ConstraintField<Conf>>
    for ParametersExpandVar<Conf, ConfG>
{
    fn new_variable<T: Borrow<ParametersExpand<Conf, GAMMA_BYTES>>>(
        cs: impl Into<Namespace<ConstraintField<Conf>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        f().and_then(|val| {
            let gamma = GammaVar::<Conf>::new_variable(
                cs.clone(),
                || {
                    Ok(val
                        .borrow()
                        .gamma_as_bytes()
                        .map_err(|_| SynthesisError::AssignmentMissing)?)
                },
                mode,
            )?;
            let client_commitment_scheme =
                ClientCommitmentSchemeParametersVar::<Conf, ConfG>::new_variable(
                    cs.clone(),
                    || Ok(&val.borrow().client_commitment_scheme),
                    mode,
                )?;
            let server_signature_scheme =
                ServerSignatureSchemeParametersVar::<_, ConfG>::new_variable(
                    cs.clone(),
                    || Ok(&val.borrow().server_signature_scheme),
                    mode,
                )?;
            let client_signature_scheme =
                ClientSignatureSchemeParametersVar::<_, ConfG>::new_variable(
                    cs.clone(),
                    || Ok(&val.borrow().client_signature_scheme),
                    mode,
                )?;
            let client_merkle_tree_scheme =
                ClientMerkleTreeParametersVar::<_, ConfG>::new_variable(
                    cs.clone(),
                    || Ok(&val.borrow().client_merkle_tree_scheme),
                    mode,
                )?;
            return Ok(Self {
                gamma,
                client_commitment_scheme,
                server_signature_scheme,
                client_signature_scheme,
                client_merkle_tree_scheme,
            });
        })
    }
}

/// All R1CS variables for the parameters of the Merkle Tree.
pub struct ClientMerkleTreeParametersVar<Conf: Config, ConfG: ConfigGadget<Conf>> {
    pub leaf_crh_scheme: ClientMerkleTreeLeafHashParametersVar<Conf, ConfG>,
    pub two_to_one_crh_scheme: ClientMerkleTreeTwoToOneHashParametersVar<Conf, ConfG>,
}

// implement variable allocation of Merkle Tree parameters
impl<Conf: Config, ConfG: ConfigGadget<Conf>>
    AllocVar<ClientMerkleTreeParameters<Conf>, ConstraintField<Conf>>
    for ClientMerkleTreeParametersVar<Conf, ConfG>
{
    fn new_variable<T: Borrow<ClientMerkleTreeParameters<Conf>>>(
        cs: impl Into<Namespace<ConstraintField<Conf>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        f().and_then(|val| {
            let leaf_crh_scheme =
                ClientMerkleTreeLeafHashParametersVar::<Conf, ConfG>::new_variable(
                    cs.clone(),
                    || Ok(&val.borrow().leaf_crh_params),
                    mode,
                )?;
            let two_to_one_crh_scheme =
                ClientMerkleTreeTwoToOneHashParametersVar::<Conf, ConfG>::new_variable(
                    cs.clone(),
                    || Ok(&val.borrow().two_to_one_crh_params),
                    mode,
                )?;
            return Ok(Self {
                leaf_crh_scheme,
                two_to_one_crh_scheme,
            });
        })
    }
}
