//! R1CS constraint generation and variable allocation for the parameters of the Base VLDP
//! scheme.

use crate::prelude::{constraints::*, *};
use crate::primitives::parameters::GammaVar;
use ark_relations::r1cs::{Namespace, SynthesisError};
use std::borrow::Borrow;

/// All R1CS variables for the parameters needed for the Base scheme.
pub struct ParametersBaseVar<Conf: Config, ConfG: ConfigGadget<Conf>> {
    pub gamma: GammaVar<Conf>,
    pub client_commitment_scheme: ClientCommitmentSchemeParametersVar<Conf, ConfG>,
    #[allow(dead_code)]
    pub server_signature_scheme: ServerSignatureSchemeParametersVar<Conf, ConfG>,
    pub client_signature_scheme: ClientSignatureSchemeParametersVar<Conf, ConfG>,
}

// implement variable allocation of all parameters
impl<Conf: Config, ConfG: ConfigGadget<Conf>, const GAMMA_BYTES: usize>
    AllocVar<ParametersBase<Conf, GAMMA_BYTES>, ConstraintField<Conf>>
    for ParametersBaseVar<Conf, ConfG>
{
    fn new_variable<T: Borrow<ParametersBase<Conf, GAMMA_BYTES>>>(
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
            return Ok(Self {
                gamma,
                client_commitment_scheme,
                server_signature_scheme,
                client_signature_scheme,
            });
        })
    }
}
