//! Locally run a server and client for the Shuffle scheme on randomly generated inputs (trusted
//! environment and communication are emulated).

use crate::circuits::CircuitShuffle;
use crate::client::*;
use crate::prelude::*;
use crate::server::*;
use ark_ff::PrimeField;
use ark_serialize::CanonicalDeserialize;
use ark_std::{end_timer, start_timer, Zero};
use astro_float::{BigFloat, Consts, Radix, RoundingMode};
use num_bigint::BigUint;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use std::str::FromStr;

/// Run the Shuffle protocol for a given gamma on random inputs (trusted environment and
/// communication are emulated).
pub fn run_protocol_shuffle<
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
    assert!(IS_REAL_INPUT || INPUT_BYTES + GAMMA_BYTES <= RANDOMNESS_BYTES);
    assert!(!IS_REAL_INPUT || 2 * INPUT_BYTES + GAMMA_BYTES <= RANDOMNESS_BYTES);
    assert!(K >= 2 && (K.ilog2() + 1) as usize <= INPUT_BYTES * 8);
    assert!(INPUT_BYTES * 8 <= ConstraintField::<Conf>::MODULUS_BIT_SIZE as usize);
    assert!(TIME_BYTES * 8 <= ConstraintField::<Conf>::MODULUS_BIT_SIZE as usize);
    let mut rng = ChaChaRng::from_entropy();
    let mut zkp_rng = Conf::ZKPRng::new();

    // setup
    let parameters = ParametersShuffle::setup(gamma, &mut rng)?;
    let (proving_key, verifying_key) = CircuitShuffle::<
        _,
        ConfG,
        INPUT_BYTES,
        TIME_BYTES,
        GAMMA_BYTES,
        RANDOMNESS_BYTES,
        K,
        IS_REAL_INPUT,
    >::keygen(parameters.clone(), &mut zkp_rng)?;
    let (client_sig_pk, client_sig_sk) =
        Conf::ClientSignatureScheme::keygen(&parameters.client_signature_scheme, &mut rng)?;
    let prf_eval_points = (0..((RANDOMNESS_BYTES - 1) / 32) + 1)
        .map(|_| rng.gen::<PRFSchemeInput<Conf>>())
        .collect::<Vec<_>>();

    // create server
    let server = ServerShuffle::<
        _,
        INPUT_BYTES,
        TIME_BYTES,
        GAMMA_BYTES,
        RANDOMNESS_BYTES,
        K,
        IS_REAL_INPUT,
    >::new(parameters.clone(), verifying_key, &mut rng)?;
    let server_sig_pk = server.get_signature_public_key();

    // create client
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
        server_sig_pk,
        client_sig_pk,
        proving_key,
    )?;

    // actual protocol
    let timer_gen_rand = start_timer!(|| "Generate randomness");

    // 1. generate randomness
    let timer_gen_rand_client = start_timer!(|| "Client generation");
    let gen_rand_client_message = client.generate_randomness_create(&mut rng)?;
    end_timer!(timer_gen_rand_client);

    let timer_gen_rand_server = start_timer!(|| "Server generation");
    let gen_rand_server_message =
        server.generate_randomness_create(&gen_rand_client_message, &mut rng)?;
    end_timer!(timer_gen_rand_server);

    let timer_verify_rand_client = start_timer!(|| "Client verification");
    let result = client.generate_randomness_verify(&gen_rand_server_message)?;
    end_timer!(timer_verify_rand_client);

    end_timer!(timer_gen_rand);

    assert!(
        result,
        "Verification of generate randomness protocol failed."
    );

    // 2. verifiable randomization
    // -- START TRUSTED ENVIRONMENT --

    let input_value = if IS_REAL_INPUT {
        let precision = INPUT_BYTES * 8 * 2;
        let input_f64 = rng.gen_range(0.0..=1.0);
        let input_bigfloat = BigFloat::from_f64(input_f64, precision);
        if input_bigfloat.is_zero() {
            BigUint::zero()
        } else {
            let input_as_string = input_bigfloat
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
        }
    } else {
        BigUint::from(rng.gen_range(1..=K))
    };

    let random_time_byte: u8 = rng.gen_range(1..u8::MAX - 1);
    let mut input_value_time = [0; TIME_BYTES];
    input_value_time[0] = random_time_byte;
    let mut lower_bound_time = [0; TIME_BYTES];
    lower_bound_time[0] = random_time_byte - 1;
    let upper_bound_time = input_value_time.clone();
    let time_bounds = (lower_bound_time, upper_bound_time);

    let mut input_value_bytes = [0; INPUT_BYTES];
    for (idx, byte) in input_value.to_bytes_le().iter().enumerate() {
        input_value_bytes[idx] = *byte;
    }

    let mut message_bytes = input_value_bytes.to_vec();
    message_bytes.extend_from_slice(&input_value_time);

    let timer_te = start_timer!(|| "Trusted environment computation");
    let input_value_signature = Conf::ClientSignatureScheme::sign(
        &parameters.client_signature_scheme,
        &client_sig_sk,
        &message_bytes,
        &mut rng,
    )?;
    end_timer!(timer_te);

    // -- END TRUSTED ENVIRONMENT --
    let timer_ver_rand = start_timer!(|| "Verifiable randomization");

    let timer_ver_rand_client = start_timer!(|| "Client generation");
    let ver_rand_client_message = client.verifiable_randomization_create::<ConfG>(
        time_bounds,
        input_value_time,
        input_value,
        input_value_signature,
        &prf_eval_points,
        &mut zkp_rng,
        false,
    )?;
    end_timer!(timer_ver_rand_client);

    let timer_ver_rand_server = start_timer!(|| "Server verification");
    let result = server.verifiable_randomization_verify::<ConfG>(
        &ver_rand_client_message,
        time_bounds,
        &prf_eval_points,
        &mut zkp_rng,
        false,
    )?;
    end_timer!(timer_ver_rand_server);

    end_timer!(timer_ver_rand);

    assert!(
        result.0,
        "Verification of verifiable randomization protocol failed."
    );

    #[cfg(feature = "print-trace")]
    {
        println!(
            "Messages sent: {}b",
            gen_rand_client_message.len()
                + gen_rand_server_message.len()
                + ver_rand_client_message.len()
        );
        println!(
            "··Generate randomness: {}b",
            gen_rand_client_message.len() + gen_rand_server_message.len()
        );
        println!("····Client message: {}b", gen_rand_client_message.len());
        println!("····Server message: {}b", gen_rand_server_message.len());
        println!(
            "··Verifiable randomization: {}b",
            ver_rand_client_message.len()
        )
    }

    Ok(())
}
