extern crate chrono;
use chrono::Local;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use rand::rngs::OsRng;
use rand::Rng;

use tfhe::prelude::*;
use tfhe::set_server_key;
use tfhe::{FheUint128, FheUint16, FheUint32, FheUint64, FheUint8};

mod constants;
mod poseidon;
mod utils;

/*
 * Implementation choices:
 * - We will start with
 *   - 32-bit primes, keys, randomness, and messages (16-bit q for schnorr)
 *   - 64-bit FheUint to handle modulo adds/mults without overflowing
 * - This implies
 *   - We will need to cast between FheUint types
 *   - we will have << 32-bit values in the FheUint64 container
 * - Genreally, for a given bit-width n, we will need 2n-bit FheUint containers
 */

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (client_key, server_keys, public_key) = utils::init_keys();
    set_server_key(server_keys);

    ////////////////////////////////////////////////////////////////////////////
    /////////// Initialization: Schnorr params, keys, and encryption ///////////
    // TODO: for now, we focus on 32-bit p, keys, and message, and 16-bit q
    ////////////////////////////////////////////////////////////////////////////
    utils::log("Generating plaintext Schnorr keys...");
    let mut rng = OsRng;
    let x_sch = rng.gen_range(1..constants::SCH_Q);
    let g_sch = BigUint::from(constants::SCH_G);
    let p_sch = BigUint::from(constants::SCH_P);
    let q_sch = constants::SCH_Q;
    let y_sch = g_sch.modpow(&BigUint::from(x_sch), &p_sch);
    // Encrypt the signing key
    utils::log("Encrypting signing Schnorr key...");
    let x_sch_enc = FheUint32::encrypt(x_sch, &client_key);

    ////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////// Signing //////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////
    utils::log("FHE signing @ server ...");
    let msg: u32 = 0xAAAAAAAA; // NOTE: this is some random 32-bit message to sign
    let msg_enc: FheUint32 = FheUint32::encrypt(msg, &public_key);
    let zero_enc: FheUint32 = FheUint32::encrypt(0u32, &public_key);

    // Generate pseudo-random nonce, as FHE(k) = H(FHE(m), FHE(x_sch)) (mod q)
    utils::log("\t Pseudorandomness as FHE(k) = H(FHE(m), FHE(x_sch)) (mod q) ...");
    let k_enc: FheUint32 =
        poseidon::poseidon_p32([&msg_enc, &x_sch_enc, &zero_enc, &(zero_enc.clone())]);
    let k_enc: FheUint32 = &k_enc % ((q_sch - 1) as u32) + 1; // ensures k in [1, q-1]
    let k_enc_up: FheUint64 = k_enc.cast_into();

    // Compute exponentiation: FHE(r) = FHE(g)^FHE(k) (mod p).
    // NOTE: need to move up to 64-bit FheUint to handle this operation
    utils::log("\t Exponentiating: FHE(k) = FHE(r) = FHE(g)^FHE(k) (mod p) ...");
    let g_enc_up: FheUint64 = FheUint32::encrypt(constants::SCH_G, &public_key).cast_into();
    let p_sch_up: u64 = p_sch.to_u64().expect("p_sch is too large");
    let r_enc_up: FheUint64 = utils::fhe2_modexp_64(&g_enc_up, &k_enc_up, p_sch_up);
    let r_enc: FheUint32 = r_enc_up.cast_into(); // already (mod p)

    // Compute hash of the message: FHE(h) = H(FHE(m), FHE(r)) (mod q)
    utils::log("\t Hashing: FHE(h) = H(FHE(m), FHE(r)) (mod q) ...");
    let h_enc: FheUint32 =
        poseidon::poseidon_p32([&msg_enc, &r_enc, &zero_enc, &(zero_enc.clone())]);
    let h_enc: FheUint32 = &h_enc % (q_sch as u32); // NOTE: ensures h in [0, q-1]

    // Compute signature: FHE(s) = (FHE(k) - FHE(x_sch) * FHE(h)) (mod q)
    utils::log("\t Signing: FHE(s) = (FHE(k) - FHE(x_sch) * FHE(h)) (mod q) ...");
    let x_sch_enc_up: FheUint64 = x_sch_enc.cast_into();
    let h_enc_up: FheUint64 = h_enc.clone().cast_into();
    let hx_enc_up: FheUint64 = (&x_sch_enc_up * &h_enc_up) % (q_sch as u64);
    let s_enc_up: FheUint64 = (k_enc_up - hx_enc_up) % (q_sch as u64);
    let s_enc: FheUint32 = s_enc_up.cast_into();

    utils::log("FHE decryption of FHE(s), FHE(h) @ client ...");
    let s_dec: u32 = s_enc.decrypt(&client_key);
    let h_dec: u32 = h_enc.decrypt(&client_key);

    ////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////// Verification /////////////////////////////
    ////////////////////////////////////////////////////////////////////////////
    utils::log("FHE signature verification @ server ...");
    // Compute r_v = g^s * y^h (mod p); here, g and y are public and s and h are decrypted
    let r_v_left = g_sch.modpow(&BigUint::from(s_dec), &p_sch);
    let r_v_right = y_sch.modpow(&BigUint::from(h_dec), &p_sch);
    let r_v = (r_v_left * r_v_right) % &p_sch;
    let r_v = r_v.to_u32().expect("r_v is too large");
    // Compute clear hash of the message: h_v = H(m, r_v) (mod q)
    let h_v = poseidon::poseidon_p32_clear([msg, r_v, 0u32, 0u32]);
    let h_v = h_v % (q_sch as u32);
    // Verify if h_v == h_dec
    let is_verified = h_v == h_dec;
    utils::log(&format!("Signature verification: {}", is_verified));

    Ok(())
}
