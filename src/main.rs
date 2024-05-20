extern crate chrono;
use chrono::Local;

// use tfhe::integer::bigint::{u256, u512};
// use tfhe::{ConfigBuilder, set_server_key, FheUint128, ClientKey, ServerKey, CompressedServerKey, PublicKey, CompactPublicKey}; // 128-bit
// use tfhe::prelude::*;

mod utils;
mod constants;

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

fn main() {
    // Hello world
    utils::say_hello();
    utils::log("Hello from {constants::SCH_P}!");
}


///////////////////////////////////////////////////////////////////////////////
// Real code below

// fn init_keys() -> (ClientKey, ServerKey, CompactPublicKey) {
//     // Generates the client secret key, server key for FHE ops, and the public key for encryption
//     utils::log("Generating keys...");
//     let config = ConfigBuilder::default().build();
//     let client_key = ClientKey::generate(config);
//     let (client_key, server_key) = generate_keys(config);
//     let public_key = CompactPublicKey::new(&client_key);
//     utils::log("Generated keys.");
//     (client_key, server_key, public_key)
// }



// fn main() -> Result<(), Box<dyn std::error::Error>> {
//     // Basic configuration to use homomorphic integers
//     let config = ConfigBuilder::default().build();

//     // Key generation
//     let (client_key, server_keys) = generate_keys(config);

//     let clear_a = 1344u32;
//     let clear_b = 5u32;
//     let clear_c = 7u8;

//     // Encrypting the input data using the (private) client_key
//     // FheUint32: Encrypted equivalent to u32
//     let mut encrypted_a = FheUint32::try_encrypt(clear_a, &client_key)?;
//     let encrypted_b = FheUint32::try_encrypt(clear_b, &client_key)?;

//     // FheUint8: Encrypted equivalent to u8
//     let encrypted_c = FheUint8::try_encrypt(clear_c, &client_key)?;

//     // On the server side:
//     set_server_key(server_keys);

//     // Clear equivalent computations: 1344 * 5 = 6720
//     let encrypted_res_mul = &encrypted_a * &encrypted_b;

//     // Clear equivalent computations: 6720 >> 5 = 210
//     encrypted_a = &encrypted_res_mul >> &encrypted_b;

//     // Clear equivalent computations: let casted_a = a as u8;
//     let casted_a: FheUint8 = encrypted_a.cast_into();

//     // Clear equivalent computations: min(210, 7) = 7
//     let encrypted_res_min = &casted_a.min(&encrypted_c);

//     // Operation between clear and encrypted data:
//     // Clear equivalent computations: 7 & 1 = 1
//     let encrypted_res = encrypted_res_min & 1_u8;

//     // Decrypting on the client side:
//     let clear_res: u8 = encrypted_res.decrypt(&client_key);
//     assert_eq!(clear_res, 1_u8);

//     Ok(())
// }