/// Run the use case from the paper on the Geodata dataset using the Shuffle VLDP scheme.
use ark_bls12_381::Bls12_381;
use ark_ed_on_bls12_381::constraints::EdwardsVar as JubJubVar;
use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
use ark_ff::{PrimeField, ToConstraintField};
use ark_groth16::Groth16;
use ark_serialize::CanonicalDeserialize;
use astro_float::BigFloat;
use csv::StringRecord;
use num_bigint::BigUint;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::collections::{HashMap, HashSet};
use std::process;
use std::str::FromStr;
use vldp::circuits::CircuitShuffle;
use vldp::client::ClientShuffle;
use vldp::config::{BasicConfig, BasicConfigGadget, Config, ConfigGadget};
use vldp::error::GenericError;
use vldp::prelude::{
    ClientCommitmentSchemeOutput, ClientSignatureSchemePublicKey, ClientSignatureSchemeSecretKey,
    ConstraintField, CryptoRng, Error, PRFSchemeInput, ParametersShuffle, Proof, ProofSystemRng,
    ProvingKey, ServerSignatureSchemePublicKey, ServerSignatureSchemeSignature, SignatureScheme,
    ZKPRng,
};
use vldp::server::ServerShuffle;

const USERS: u16 = 182;

#[derive(Debug)]
struct GeoDataRecord {
    user: u16,
    day: u8,
    postcode: String,
}

impl TryFrom<StringRecord> for GeoDataRecord {
    type Error = Error;

    fn try_from(value: StringRecord) -> Result<Self, Self::Error> {
        let user = value
            .get(0)
            .ok_or_else(|| GenericError::ParseError("No user found!".to_string()))?;
        let day = value
            .get(1)
            .ok_or(GenericError::ParseError("No day found!".to_string()))?;
        let postcode = value
            .get(4)
            .ok_or(GenericError::ParseError("No postcode found".to_string()))?
            .to_string();
        Ok(Self {
            user: user.parse()?,
            day: day.parse()?,
            postcode,
        })
    }
}

fn load_data() -> Result<(Vec<GeoDataRecord>, HashMap<String, u64>), Error> {
    let mut reader = csv::Reader::from_path(
        "resources/shuffle-model-parameters/geolife-postcodes-condensed-empties.csv",
    )?;
    let mut records = reader
        .records()
        .flat_map(|record| record.map(|record| record.try_into()))
        .collect::<Result<Vec<GeoDataRecord>, _>>()?;
    records.sort_by(|a, b| {
        let day_comparison = a.day.cmp(&b.day);
        if day_comparison.is_eq() {
            a.user.cmp(&b.user)
        } else {
            day_comparison
        }
    });
    let unique_postcodes = records
        .iter()
        .map(|x| x.postcode.clone())
        .collect::<HashSet<String>>();
    let mut postcode_bin_map = HashMap::new();
    for (idx, postcode) in unique_postcodes.into_iter().enumerate() {
        let result = postcode_bin_map.insert(postcode, idx as u64);
        assert!(result.is_none());
    }
    Ok((records, postcode_bin_map))
}

fn setup<
    Conf: Config,
    ConfG: ConfigGadget<Conf>,
    R: Rng + CryptoRng,
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
        ParametersShuffle<Conf, GAMMA_BYTES>,
        ProvingKey<Conf>,
        ServerShuffle<
            Conf,
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
    let parameters = ParametersShuffle::setup(gamma, rng)?;
    let (proving_key, verifying_key) = CircuitShuffle::<
        _,
        ConfG,
        INPUT_BYTES,
        TIME_BYTES,
        GAMMA_BYTES,
        RANDOMNESS_BYTES,
        K,
        IS_REAL_INPUT,
    >::keygen(parameters.clone(), zkp_rng)?;

    // create server
    let server = ServerShuffle::<
        _,
        INPUT_BYTES,
        TIME_BYTES,
        GAMMA_BYTES,
        RANDOMNESS_BYTES,
        K,
        IS_REAL_INPUT,
    >::new(parameters.clone(), verifying_key, rng)?;

    // create clients
    let mut client_public_keys = Vec::with_capacity(USERS as usize);
    let mut client_secret_keys = Vec::with_capacity(USERS as usize);
    for _ in 0..USERS {
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
    ServerSignatureSchemePublicKey<Conf>: ToConstraintField<ConstraintField<Conf>>,
    ClientCommitmentSchemeOutput<Conf>: CanonicalDeserialize,
    ClientSignatureSchemePublicKey<Conf>: CanonicalDeserialize,
    ServerSignatureSchemeSignature<Conf>: CanonicalDeserialize,
    Proof<Conf>: CanonicalDeserialize,
{
    let (records, postcode_bin_map) = load_data()?;
    // setup
    let mut rng = ChaChaRng::from_entropy();
    let mut zkp_rng = Conf::ZKPRng::new();
    let (parameters, proving_key, server, client_public_keys, client_secret_keys) =
        setup::<
            Conf,
            ConfG,
            _,
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
        if record.user % 100 == 0 {
            println!("{}", record.user)
        }
        let client_public_key = client_public_keys[record.user as usize].clone();
        let client_secret_key = client_secret_keys[record.user as usize].clone();
        let mut client = ClientShuffle::<
            _,
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
        let input_value = BigUint::from(*postcode_bin_map.get(&record.postcode).unwrap());

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
            &mut zkp_rng,
            true,
        )?;
        let result = server.verifiable_randomization_verify::<ConfG>(
            &ver_rand_client_message,
            time_bounds,
            &prf_eval_points,
            &mut zkp_rng,
            true,
        )?;
        assert!(
            result.0,
            "Verification of verifiable randomization protocol failed."
        );
        ldp_values.push(result.1);

        if record.user == USERS - 1 {
            println!("Day {}:", record.day);
            println!("Estimate:");
            for (postcode, &bin) in postcode_bin_map.iter() {
                let count = ldp_values.iter().filter(|&&x| x == bin).count();
                println!("{postcode}: {count}");
            }
            ldp_values.clear();
        }
    }
    Ok(())
}

fn main() {
    // protocol settings
    const INPUT_BYTES: usize = 8;
    const TIME_BYTES: usize = 1;
    const GAMMA_BYTES: usize = 8;
    const K: u64 = 8;
    const IS_REAL_INPUT: bool = false;
    const RANDOMNESS_BYTES: usize = if IS_REAL_INPUT {
        GAMMA_BYTES + 2 * INPUT_BYTES
    } else {
        GAMMA_BYTES + INPUT_BYTES
    };

    // gamma value
    let gamma = BigFloat::from_str("0.41750056279375136").unwrap();

    // curve selection
    type PairingCurve = Bls12_381;
    type InnerCurve = JubJub;
    type InnerCurveVar = JubJubVar;

    // zkp scheme selection
    type ZKPRng = ChaChaRng;
    type ZKPScheme = Groth16<PairingCurve>;

    if let Err(e) = run::<
        BasicConfig<InnerCurve, ZKPRng, ZKPScheme, 32>,
        BasicConfigGadget<InnerCurve, InnerCurveVar>,
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
