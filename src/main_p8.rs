extern crate chrono;
use chrono::Local;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use rand::rngs::OsRng;
use rand::Rng;

use tfhe::prelude::*;
use tfhe::set_server_key;
use tfhe::{FheUint128, FheUint16, FheUint32, FheUint64, FheUint8};

// mod constants;
// mod poseidon;
// mod poseidon_p8;
// mod utils;
use crate::constants;
use crate::poseidon_p8;
use crate::utils;


/*
 * Implementation choices:
 * - We will start with
 *   - 8-bit primes, keys, randomness, and messages (16-bit q for schnorr)
 *   - 16-bit FheUint to handle modulo adds/mults without overflowing
 * - This implies
 *   - We will need to cast between FheUint types
 *   - we will have << 8-bit values in the FheUint16 container
 * - Genreally, for a given bit-width n, we will need 2n-bit FheUint containers
 */

fn main_p8() -> Result<(), Box<dyn std::error::Error>> {
    let (client_key, server_keys, public_key) = utils::init_keys();
    set_server_key(server_keys);

    ////////////////////////////////////////////////////////////////////////////
    /////////// Initialization: Schnorr params, keys, and encryption ///////////
    // TODO: for now, we focus on 8-bit p, keys, and message, and 16-bit q
    ////////////////////////////////////////////////////////////////////////////
    utils::log("Generating plaintext Schnorr keys...");
    let mut rng = OsRng;
    let x_sch = rng.gen_range(1..constants::SCH_Q);
    // let x_sch = 1u8;  // EXP: fix a secret key
    let g_sch = BigUint::from(constants::SCH_G_8);
    let p_sch = BigUint::from(constants::SCH_P_8);
    let q_sch = constants::SCH_Q_4;
    let y_sch = g_sch.modpow(&BigUint::from(x_sch), &p_sch);
    utils::log(&format!(
        "DEBUG x_sch: {}, g_sch: {}, p_sch: {}, q_sch: {}, y_sch: {}",
        x_sch, g_sch, p_sch, q_sch, y_sch
    ));

    // Encrypt the signing key
    utils::log("Encrypting signing Schnorr key...");
    let x_sch_enc = FheUint8::encrypt(x_sch, &client_key);

    ////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////// Signing //////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////
    utils::log("FHE signing @ server ...");
    // let msg: u8 = 0xAAAAAAAA; // EXP: this is some random 8-bit message to sign; swappable
    let msg: u8 = 0xAA; // EXP: this is some random 8-bit message to sign; swappable
    let msg_enc: FheUint8 = FheUint8::encrypt(msg, &public_key);
    let zero_enc: FheUint8 = FheUint8::encrypt(0u8, &public_key);
    let zero_enc2: FheUint8 = FheUint8::encrypt(0u8, &public_key);

    // Generate pseudo-random nonce, as FHE(k) = H(FHE(m), FHE(x_sch)) (mod q)
    utils::log("\t Pseudorandomness as FHE(k) = H(FHE(m), FHE(x_sch)) (mod q) ...");
    let k_enc: FheUint8 =
        poseidon_p8::poseidon_p8_rf2_rp1([&msg_enc, &x_sch_enc, &zero_enc, &zero_enc2]);
    let k_enc: FheUint8 = &k_enc % ((q_sch - 1) as u8) + 1; // ensures k in [1, q-1]
    let k_enc_up: FheUint16 = (&k_enc).clone().cast_into();

    // #DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG
    let k_enc_dec: u8 = k_enc.decrypt(&client_key);
    utils::log(&format!(
        "DEBUG k_clear from direct hash: {}",
        poseidon_p8::poseidon_p8_clear_rf2_rp1([msg, x_sch, 0u8, 0u8])
    ));
    utils::log(&format!("DEBUG k_enc_dec: {}", k_enc_dec));

    // Compute exponentiation: FHE(r) = FHE(g)^FHE(k) (mod p).
    // NOTE: need to move up to 16-bit FheUint to handle this operation
    utils::log("\t Exponentiating: FHE(k) = FHE(r) = FHE(g)^FHE(k) (mod p) ...");
    let g_enc_up: FheUint16 = FheUint8::encrypt(constants::SCH_G, &public_key).cast_into();
    let p_sch_up: u16 = p_sch.to_u16().expect("p_sch is too large");
    let r_enc_up: FheUint16 = utils::fhe2_modexp_16(&g_enc_up, &k_enc_up, p_sch_up);
    let r_enc: FheUint8 = r_enc_up.cast_into(); // already (mod p)

    // Compute hash of the message: FHE(h) = H(FHE(m), FHE(r)) (mod q)
    utils::log("\t Hashing: FHE(h) = H(FHE(m), FHE(r)) (mod q) ...");
    let h_enc: FheUint8 =
        poseidon_p8::poseidon_p8_rf2_rp1([&msg_enc, &r_enc, &zero_enc, &zero_enc2]);
    let h_enc: FheUint8 = &h_enc % (q_sch as u8); // NOTE: ensures h in [0, q-1]

    // Compute signature: FHE(s) = (FHE(k) - FHE(x_sch) * FHE(h)) (mod q)
    utils::log("\t Signing: FHE(s) = (FHE(k) - FHE(x_sch) * FHE(h)) (mod q) ...");
    let x_sch_enc_up: FheUint16 = x_sch_enc.clone().cast_into();
    let h_enc_up: FheUint16 = (&h_enc).clone().cast_into();
    let hx_enc_up: FheUint16 = (&x_sch_enc_up * &h_enc_up) % (q_sch as u16);
    // Extra add q_sch to handle case if hx_enc_up > k_enc_up;
    // since we use 2x bit width there is no overflow.
    let s_enc_up: FheUint16 = (&k_enc_up + (q_sch as u16) - &hx_enc_up) % (q_sch as u16);
    let s_enc: FheUint8 = s_enc_up.clone().cast_into();

    utils::log("FHE decryption of FHE(s), FHE(h) @ client ...");
    let s_dec: u8 = (&s_enc).clone().decrypt(&client_key);
    let h_dec: u8 = (&h_enc).clone().decrypt(&client_key);

    //  DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG
    let hx_dec: u16 = (x_sch as u16 * h_dec as u16) % (q_sch as u16);
    let hx_enc_dec: u16 = hx_enc_up.clone().decrypt(&client_key);  // hx_enc_up not used anymore
    let r_enc_dec: u8 = (&r_enc).clone().decrypt(&client_key);
    let k_enc_dec: u16 = (&k_enc_up).clone().decrypt(&client_key);
    utils::log(&format!(
        "k_enc_dec: {}, r_enc_dec: {}, h_dec: {}, hx_dec: {}, hx_enc_dec: {}, s_dec: {}",
        k_enc_dec, r_enc_dec, h_dec, hx_dec, hx_enc_dec, s_dec,
    ));

    ////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////// Verification /////////////////////////////
    ////////////////////////////////////////////////////////////////////////////
    utils::log("FHE signature verification @ server ...");
    // Compute r_v = g^s * y^h (mod p); here, g and y are public and s and h are decrypted
    let r_v_left = g_sch.modpow(&BigUint::from(s_dec), &p_sch);
    let r_v_right = y_sch.modpow(&BigUint::from(h_dec), &p_sch);
    let r_v = (&r_v_left * &r_v_right) % &p_sch;
    let r_v = r_v.to_u8().expect("r_v is too large");
    // Compute clear hash of the message: h_v = H(m, r_v) (mod q)
    let h_v = poseidon_p8::poseidon_p8_clear_rf2_rp1([msg, r_v, 0u8, 0u8]);
    let h_v = h_v % (q_sch as u8);
    // Verify if h_v == h_dec
    // DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG
    utils::log(&format!(
        "h_v: {}, h_dec: {}, r_v: {}, r_v_left: {}, r_v_right: {}",
        h_v, h_dec, r_v, &r_v_left, &r_v_right
    ));
    let is_verified = h_v == h_dec;
    utils::log(&format!("Signature verification: {}", is_verified));

    Ok(())
}
