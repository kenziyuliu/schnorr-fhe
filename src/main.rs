extern crate chrono;
use chrono::Local;
use rand::Rng;
use rand::rngs::OsRng;
use num_bigint::BigUint;
use num_traits::ToPrimitive;

use tfhe::{set_server_key, FheUint128, ClientKey, ServerKey, CompressedServerKey, PublicKey, CompactPublicKey}; // 128-bit
use tfhe::{FheUint32, FheUint8};
use tfhe::prelude::*;

mod utils;
mod constants;
mod poseidon;

/*
 * Implementation choices:
 * - We use 128-bit integers for the homomorphic encryption. This implies
 *   - We will use up to a 128-bit prime for Poseidon prime field (p < 2^128)
 *   - The message will be 64-bit (m < 2^64)
 *   - The randomness (r) will be 64-bit (r < 2^64)
 *   - Small 64-bit numbers so that whatever prime we choose, we can always
 *     operate the numbers with FheUint64 without overflow
 * - Later, we can double the bitwidth for all integers involved
 * - Schnorr
 *   - Schnorr involves picking
 */


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (client_key, server_keys, public_key) = utils::init_keys();


    ////// Initialization: Schnorr params, keys, and encryption //////
    utils::log("Generating plaintext Schnorr keys...");
    let mut rng = OsRng;
    let x_sch = BigUint::from(rng.gen_range(1..constants::SCH_Q_64));
    let g_sch = BigUint::from(constants::SCH_G_128);
    let p_sch = BigUint::from(constants::SCH_P_128);
    let q_sch = BigUint::from(constants::SCH_Q_64);
    let y_sch = g_sch.modpow(&x_sch, &p_sch);
    // Convert back to plain integers
    let x_sch = x_sch.to_u128().expect("x_sch is too large");
    let y_sch = y_sch.to_u128().expect("y_sch is too large");
    // Encrypt the signing key
    utils::log("Encrypting signing Schnorr key...");
    let x_sch_enc = FheUint128::try_encrypt(x_sch, &client_key)?;


    ////// Signing //////

    // TODO: for now, we will use hardcoded numbers as the "randomness"
    // for the signature. In principle, this can be the



    utils::log("Encrypting data...");
    let clear_a = 1344u32;
    let clear_b = 5u32;
    let clear_c = 7u8;

    // Encrypting the input data using the (private) client_key
    // FheUint32: Encrypted equivalent to u32
    let mut encrypted_a = FheUint32::try_encrypt(clear_a, &client_key)?;
    let encrypted_b = FheUint32::try_encrypt(clear_b, &client_key)?;

    // FheUint8: Encrypted equivalent to u8
    let encrypted_c = FheUint8::try_encrypt(clear_c, &client_key)?;

    // On the server side:
    set_server_key(server_keys);

    // Clear equivalent computations: 1344 * 5 = 6720
    utils::log("Server performing multiplication...");
    let encrypted_res_mul = &encrypted_a * &encrypted_b;

    // Clear equivalent computations: 6720 >> 5 = 210
    utils::log("Server performing right shift...");
    encrypted_a = &encrypted_res_mul >> &encrypted_b;

    // Clear equivalent computations: let casted_a = a as u8;
    let casted_a: FheUint8 = encrypted_a.cast_into();

    // Clear equivalent computations: min(210, 7) = 7
    utils::log("Server performing min...");
    let encrypted_res_min = &casted_a.min(&encrypted_c);

    // Operation between clear and encrypted data:
    // Clear equivalent computations: 7 & 1 = 1
    utils::log("Server performing bitwise AND...");
    let encrypted_res = encrypted_res_min & 1_u8;

    // Decrypting on the client side:
    utils::log("Client decrypting result...");
    let clear_res: u8 = encrypted_res.decrypt(&client_key);
    assert_eq!(clear_res, 1_u8);

    Ok(())
}