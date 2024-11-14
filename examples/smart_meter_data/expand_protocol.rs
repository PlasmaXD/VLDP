/// Run the use case from the paper on the Smart meter dataset using the Expand VLDP scheme.
use ark_bls12_381::Bls12_381;
use ark_ed_on_bls12_381::constraints::EdwardsVar as JubJubVar;
use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
use ark_ff::{PrimeField, ToConstraintField};
use ark_groth16::Groth16;
use ark_serialize::CanonicalDeserialize;
use ark_std::Zero;
use astro_float::{BigFloat, Consts, Radix, RoundingMode};
use csv::StringRecord;
use num_bigint::BigUint;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::process;
use std::str::FromStr;
use vldp::circuits::CircuitExpand;
use vldp::client::ClientExpand;
use vldp::config::{BasicConfig, BasicConfigGadget, Config, ConfigGadget};
use vldp::error::GenericError;
use vldp::prelude::{
    ClientMerkleTreeRoot, ClientSignatureSchemePublicKey, ClientSignatureSchemeSecretKey,
    ConstraintField, CryptoRng, Error, PRFSchemeInput, ParametersExpand, Proof, ProofSystemRng,
    ProvingKey, ServerSignatureSchemeSignature, SignatureScheme, ZKPRng,
};
use vldp::server::ServerExpand;

const HOUSEHOLDS: u16 = 5566;
const MAX_VALUE: f64 = 0.3527045043460217;

#[derive(Debug)]
struct SmartMeterRecord {
    household: u16,
    day: u8,
    average_energy: BigFloat,
}

impl TryFrom<StringRecord> for SmartMeterRecord {
    type Error = Error;

    fn try_from(value: StringRecord) -> Result<Self, Self::Error> {
        let househould = value
            .get(0)
            .ok_or_else(|| GenericError::ParseError("No household found!".to_string()))?;
        let day = value
            .get(1)
            .ok_or(GenericError::ParseError("No day found!".to_string()))?;
        let average_energy = value.get(2).ok_or(GenericError::ParseError(
            "No average energy found".to_string(),
        ))?;
        let average_energy = BigFloat::from_str(average_energy)?;
        if average_energy.is_nan() {
            Err(GenericError::ParseError(
                "Invalid average energy found.".to_string(),
            ))?
        } else {
            Ok(Self {
                household: househould.parse()?,
                day: day.parse()?,
                average_energy,
            })
        }
    }
}

fn load_data() -> Result<Vec<SmartMeterRecord>, Error> {
    let mut reader = csv::Reader::from_path("resources/shuffle-model-parameters/energy_data.csv")?;
    let mut records = reader
        .records()
        .flat_map(|record| record.map(|record| record.try_into()))
        .collect::<Result<Vec<SmartMeterRecord>, _>>()?;
    let max_value = BigFloat::from_f64(MAX_VALUE, 100);
    for record in records.iter_mut() {
        record.average_energy = record
            .average_energy
            .div(&max_value, 100, RoundingMode::None);
    }
    Ok(records)
}

fn setup<
    Conf: Config,
    ConfG: ConfigGadget<Conf>,
    R: Rng + CryptoRng,
    const MT_DEPTH: usize,
    const INPUT_BYTES: usize,
    const TIME_BYTES: usize,
    const GAMMA_BYTES: usize,
    const RANDOMNESS_BYTES: usize,
    const K: u64,
    const IS_REAL_INPUT: bool,
>(
    gamma: BigFloat,
    rng: &mut R,
    zkp_rng: &mut ZKPRng<Conf>,
) -> Result<
    (
        ParametersExpand<Conf, GAMMA_BYTES>,
        ProvingKey<Conf>,
        ServerExpand<
            Conf,
            MT_DEPTH,
            INPUT_BYTES,
            TIME_BYTES,
            GAMMA_BYTES,
            RANDOMNESS_BYTES,
            K,
            IS_REAL_INPUT,
        >,
        Vec<ClientSignatureSchemePublicKey<Conf>>,
        Vec<ClientSignatureSchemeSecretKey<Conf>>,
    ),
    Error,
> {
    assert!(IS_REAL_INPUT || INPUT_BYTES + GAMMA_BYTES == RANDOMNESS_BYTES);
    assert!(!IS_REAL_INPUT || 2 * INPUT_BYTES + GAMMA_BYTES == RANDOMNESS_BYTES);
    assert!(K >= 2 && (K.ilog2() + 1) as usize <= INPUT_BYTES * 8);
    assert!(INPUT_BYTES * 8 <= ConstraintField::<Conf>::MODULUS_BIT_SIZE as usize);
    assert!(GAMMA_BYTES * 8 <= ConstraintField::<Conf>::MODULUS_BIT_SIZE as usize);
    assert!(TIME_BYTES * 8 <= ConstraintField::<Conf>::MODULUS_BIT_SIZE as usize);

    // setup
    let parameters = ParametersExpand::setup(gamma, rng)?;
    let (proving_key, verifying_key) = CircuitExpand::<
        _,
        ConfG,
        MT_DEPTH,
        INPUT_BYTES,
        TIME_BYTES,
        GAMMA_BYTES,
        RANDOMNESS_BYTES,
        K,
        IS_REAL_INPUT,
    >::keygen(parameters.clone(), zkp_rng)?;

    // create server
    let server = ServerExpand::<
        _,
        MT_DEPTH,
        INPUT_BYTES,
        TIME_BYTES,
        GAMMA_BYTES,
        RANDOMNESS_BYTES,
        K,
        IS_REAL_INPUT,
    >::new(parameters.clone(), verifying_key, rng)?;

    // create clients
    let mut client_public_keys = Vec::with_capacity(HOUSEHOLDS as usize);
    let mut client_secret_keys = Vec::with_capacity(HOUSEHOLDS as usize);
    for _ in 0..HOUSEHOLDS {
        let (client_sig_pk, client_sig_sk) =
            Conf::ClientSignatureScheme::keygen(&parameters.client_signature_scheme, rng)?;

        client_public_keys.push(client_sig_pk);
        client_secret_keys.push(client_sig_sk);
    }

    Ok((
        parameters,
        proving_key,
        server,
        client_public_keys,
        client_secret_keys,
    ))
}

fn run<
    Conf: Config,
    ConfG: ConfigGadget<Conf>,
    const MT_DEPTH: usize,
    const INPUT_BYTES: usize,
    const TIME_BYTES: usize,
    const GAMMA_BYTES: usize,
    const RANDOMNESS_BYTES: usize,
    const K: u64,
    const IS_REAL_INPUT: bool,
>(
    gamma: BigFloat,
) -> Result<(), Error>
where
    ClientSignatureSchemePublicKey<Conf>:
        ToConstraintField<ConstraintField<Conf>> + CanonicalDeserialize,
    ClientMerkleTreeRoot<Conf>: ToConstraintField<ConstraintField<Conf>>,
    ServerSignatureSchemeSignature<Conf>: CanonicalDeserialize,
    Proof<Conf>: CanonicalDeserialize,
{
    let records = load_data()?;
    // setup
    let mut rng = ChaChaRng::from_entropy();
    let mut zkp_rng = Conf::ZKPRng::new();
    let (parameters, proving_key, server, client_public_keys, client_secret_keys) =
        setup::<
            Conf,
            ConfG,
            _,
            MT_DEPTH,
            INPUT_BYTES,
            TIME_BYTES,
            GAMMA_BYTES,
            RANDOMNESS_BYTES,
            K,
            IS_REAL_INPUT,
        >(gamma.clone(), &mut rng, &mut zkp_rng)?;
    let server_sig_pk = server.get_signature_public_key();
    let prf_eval_points = (0..((RANDOMNESS_BYTES - 1) / 32) + 1)
        .map(|_| rng.gen::<PRFSchemeInput<Conf>>())
        .collect::<Vec<_>>();

    let mut ldp_values = vec![];

    for record in records.iter() {
        if record.household % 100 == 0 {
            println!("{}", record.household)
        }
        let client_public_key = client_public_keys[record.household as usize].clone();
        let client_secret_key = client_secret_keys[record.household as usize].clone();
        let mut client = ClientExpand::<
            _,
            MT_DEPTH,
            INPUT_BYTES,
            TIME_BYTES,
            GAMMA_BYTES,
            RANDOMNESS_BYTES,
            K,
            IS_REAL_INPUT,
        >::new(
            parameters.clone(),
            server_sig_pk.clone(),
            client_public_key,
            proving_key.clone(),
        )?;
        // generate randomness
        let gen_rand_client_message = client.generate_randomness_create(&mut rng)?;
        let gen_rand_server_message =
            server.generate_randomness_create(&gen_rand_client_message, &mut rng)?;
        let result = client.generate_randomness_verify(&gen_rand_server_message)?;
        assert!(
            result,
            "Verification of generate randomness protocol failed."
        );

        // input data from trusted environment
        let input_value = if record.average_energy.is_zero() {
            BigUint::zero()
        } else {
            let precision = INPUT_BYTES * 8 * 2;
            let input_as_string = record
                .average_energy
                .mul_full_prec(
                    &BigFloat::from_u8(2, precision)
                        .powi(INPUT_BYTES * 8, precision, RoundingMode::Down)
                        .sub_full_prec(&BigFloat::from_u8(1, precision)),
                )
                .int()
                .convert_to_radix(
                    Radix::Dec,
                    RoundingMode::None,
                    &mut Consts::new().expect("Constants cache initialization should not fail."),
                )?
                .1
                .iter()
                .map(|digit| digit.to_string())
                .collect::<String>();
            if input_as_string.is_empty() {
                BigUint::zero()
            } else {
                BigUint::from_str(&input_as_string).expect("This parse should not fail.")
            }
        };

        let mut input_value_time = [0; TIME_BYTES];
        input_value_time[0] = record.day + 1;
        let mut lower_bound_time = [0; TIME_BYTES];
        lower_bound_time[0] = record.day;
        let time_bounds = (lower_bound_time, input_value_time.clone());

        let mut input_value_bytes = [0; INPUT_BYTES];
        for (idx, byte) in input_value.to_bytes_le().iter().enumerate() {
            input_value_bytes[idx] = *byte;
        }

        let mut message_bytes = input_value_bytes.to_vec();
        message_bytes.extend_from_slice(&input_value_time);

        let input_value_signature = Conf::ClientSignatureScheme::sign(
            &parameters.client_signature_scheme,
            &client_secret_key,
            &message_bytes,
            &mut rng,
        )?;

        // verifiable randomizations
        let ver_rand_client_message = client.verifiable_randomization_create::<ConfG>(
            time_bounds,
            input_value_time,
            input_value.clone(),
            input_value_signature,
            &prf_eval_points,
            record.day as usize,
            &mut zkp_rng,
            true,
        )?;
        let result = server.verifiable_randomization_verify::<ConfG>(
            &ver_rand_client_message,
            time_bounds,
            &prf_eval_points,
            record.day as usize,
            &mut zkp_rng,
            true,
        )?;
        assert!(
            result.0,
            "Verification of verifiable randomization protocol failed."
        );
        ldp_values.push(result.1);

        if record.household == HOUSEHOLDS - 1 {
            let max_value = BigFloat::from_f64(MAX_VALUE, 100);
            let sample_sum = ldp_values.iter().sum::<u64>() as f64;
            let estimate = BigFloat::from_f64(sample_sum / K as f64, 100)
                .sub(
                    &gamma.mul(
                        &BigFloat::from_f64(HOUSEHOLDS as f64 / 2.0, 100),
                        100,
                        RoundingMode::None,
                    ),
                    100,
                    RoundingMode::None,
                )
                .div(
                    &(BigFloat::from_u8(1, 100).sub(&gamma, 100, RoundingMode::None)),
                    100,
                    RoundingMode::None,
                )
                .div(
                    &BigFloat::from_f64(HOUSEHOLDS as f64, 100),
                    100,
                    RoundingMode::None,
                );
            let estimate = estimate.mul(&max_value, 100, RoundingMode::None);
            println!("Day {}:", record.day);
            println!("Estimate: {estimate}");
            ldp_values.clear();
        }
    }
    Ok(())
}

fn main() {
    // define Merkle Tree depth
    const MT_DEPTH: usize = 3;

    // protocol settings
    const INPUT_BYTES: usize = 8;
    const TIME_BYTES: usize = 1;
    const GAMMA_BYTES: usize = 8;
    const K: u64 = 10;
    const IS_REAL_INPUT: bool = true;
    const RANDOMNESS_BYTES: usize = if IS_REAL_INPUT {
        GAMMA_BYTES + 2 * INPUT_BYTES
    } else {
        GAMMA_BYTES + INPUT_BYTES
    };

    // gamma value
    let gamma = BigFloat::from_str("0.5006005204469973").unwrap();

    // curve selection
    type PairingCurve = Bls12_381;
    type InnerCurve = JubJub;
    type InnerCurveVar = JubJubVar;

    // zkp scheme selection
    type ZKPRng = ChaChaRng;
    type ZKPScheme = Groth16<PairingCurve>;

    if let Err(e) = run::<
        BasicConfig<InnerCurve, ZKPRng, ZKPScheme, RANDOMNESS_BYTES>,
        BasicConfigGadget<InnerCurve, InnerCurveVar>,
        MT_DEPTH,
        INPUT_BYTES,
        TIME_BYTES,
        GAMMA_BYTES,
        RANDOMNESS_BYTES,
        K,
        IS_REAL_INPUT,
    >(gamma)
    {
        eprintln!("Error occurred: {e}");
        process::exit(1);
    }
}
