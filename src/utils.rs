extern crate chrono;
use chrono::Local;

use tfhe::prelude::*;
use tfhe::{
    generate_keys, ClientKey, CompactPublicKey, ConfigBuilder, FheUint128,
    FheUint16, FheUint32, FheUint64, ServerKey,
};

// pub fn say_hello() {
//     println!("Hello from utils!");
// }

// Log a message with the current time
pub fn log(msg: &str) {
    let now = Local::now();
    println!("{now} {msg}");
}

pub fn init_keys() -> (ClientKey, ServerKey, CompactPublicKey) {
    // Generates the client secret key, server key for FHE ops, and the public key for encryption
    log("Generating keys...");
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    let public_key = CompactPublicKey::new(&client_key);
    log("Generated keys.");
    (client_key, server_key, public_key)
}

/*
pub fn init_keys_gpu() -> (ClientKey, ServerKey, CompactPublicKey) {
    // Generates the client secret key, server key for FHE ops, and the public key for encryption
    log("Generating keys...");
    let config = ConfigBuilder::default().build();
    let client_key = ClientKey::generate(config);
    let public_key = CompactPublicKey::new(&client_key);
    let compressed_server_key = CompressedServerKey::new(&client_key);
    let gpu_server_key = compressed_server_key.decompress_to_gpu();
    log("Generated keys.");
    (client_key, gpu_server_key, public_key)
}
*/

// Naive exponentiation of a FheUint
pub fn fhe_exp_128_naive(base: &FheUint128, exp: u128) -> FheUint128 {
    let mut result = base.clone();
    for _ in 1..exp {
        result = result * base.clone();
    }
    result
}

// Fast exponentiation of a FheUint
pub fn fhe_exp_128(base: &FheUint128, exp: u128) -> FheUint128 {
    let mut result = base.clone();
    let mut exp = exp;
    let mut base = base.clone();
    while exp > 1 {
        if exp % 2 == 0 {
            base = &base * &base;
            exp = exp / 2;
        } else {
            result = result * base.clone();
            exp = exp - 1;
        }
    }
    result
}

// FheUint64 exponentiation
pub fn fhe_exp_64_naive(base: &FheUint64, exp: u64) -> FheUint64 {
    let mut result = base.clone();
    for _ in 1..exp {
        result = result * base.clone();
    }
    result
}

pub fn fhe_exp_64(base: &FheUint64, exp: u64) -> FheUint64 {
    if exp == 0 {
        // If exp is 0 we need to return an FheUint64 with value 1,
        // but we can't use the FheUint64::encrypt method because it requires a ClientKey
        panic!("Exponent should be greater than 0");
    }
    let mut result = base.clone();
    let mut exp = exp - 1; // -1 because init result is base
    let mut base = base.clone();
    while exp > 0 {
        if exp % 2 == 1 {
            result = &result * &base;
        }
        base = &base * &base;
        exp /= 2;
    }
    result
}

pub fn fhe_modexp_64(base: &FheUint64, exp: u64, modval: u64) -> FheUint64 {
    if exp == 0 {
        // If exp is 0 we need to return an FheUint64 with value 1,
        // but we can't use the FheUint64::encrypt method because it requires a ClientKey
        panic!("Exponent should be greater than 0");
    }
    let mut result = base.clone();
    let mut exp = exp - 1; // -1 because init result is base
    let mut base = base.clone();
    while exp > 0 {
        if exp % 2 == 1 {
            result = &(&result * &base) % modval;
        }
        base = &(&base * &base) % modval;
        exp /= 2;
    }
    result
}

// FheUint32 exponentiation
pub fn fhe_exp_32_naive(base: &FheUint32, exp: u32) -> FheUint32 {
    let mut result = base.clone();
    for _ in 1..exp {
        result = result * base.clone();
    }
    result
}

pub fn fhe_exp_32(base: &FheUint32, exp: u32) -> FheUint32 {
    if exp == 0 {
        // If exp is 0 we need to return an FheUint32 with value 1,
        // but we can't use the FheUint32::encrypt method because it requires a ClientKey
        panic!("Exponent should be greater than 0");
    }
    let mut result = base.clone();
    let mut exp = exp - 1; // -1 because init result is base
    let mut base = base.clone();
    while exp > 0 {
        if exp % 2 == 1 {
            result = &result * &base;
        }
        base = &base * &base;
        exp /= 2;
    }
    result
}

pub fn fhe_exp_16_naive(base: &FheUint16, exp: u16) -> FheUint16 {
    let mut result = base.clone();
    for _ in 1..exp {
        result = result * base.clone();
    }
    result
}

pub fn fhe_exp_16(base: &FheUint16, exp: u16) -> FheUint16 {
    if exp == 0 {
        // If exp is 0 we need to return an FheUint16 with value 1,
        // but we can't use the FheUint16::encrypt method because it requires a ClientKey
        panic!("Exponent should be greater than 0");
    }
    let mut result = base.clone();
    let mut exp = exp - 1; // -1 because init result is base
    let mut base = base.clone();
    while exp > 0 {
        if exp % 2 == 1 {
            result = &result * &base;
        }
        base = &base * &base;
        exp /= 2;
    }
    result
}

///////////////////////////////////////////////////////////////////////////////
///////// Fast FHE exponentiation with both FHE base and FHE exponent /////////
///////////////////////////////////////////////////////////////////////////////

/*
 * notes
 *   - for `fhe_exp(base: fhe, exp: fhe) -> fhe`, you will just have to
 *     operate without considerating for overflow (around the FheUint bitwidth)
 *   - for `fhe_exp(base: fhe, exp: fhe, modval: clear) -> fhe`, we will assume
 *     that the multiplications do NOT overflow the bitwidth of the FheUint
 *     (or else `% modval` wont be correct)
 *   - this means that for the exp impl, we won't worry about overflow,
 *     but the input FheUint should be large enough to handle the result
 */

pub fn fhe2_modexp_64(base_enc: &FheUint64, exp_enc: &FheUint64, modval: u64) -> FheUint64 {
    // Fast exponentiation of FheUint64 with FheUint64 exponent
    // NOTE: assumes that the multiplications do not overflow the bitwidth of the FheUint
    // NOTE: assumes that exp != 0, or else we need to return FHE(1) but public key is required
    let mut result = base_enc.clone();
    let mut base_accum = base_enc.clone();
    let mut exp_enc = exp_enc - 1;

    for _i in 0..64 {
        let is_even = (&exp_enc & 1).eq(1);
        let result_if_even = (&result * &base_accum) % modval;
        result = is_even.if_then_else(&result_if_even, &result);
        base_accum = (&base_accum * &base_accum) % modval;
        exp_enc >>= 1u64;
    }
    result
}

pub fn fhe2_modexp_16(base_enc: &FheUint16, exp_enc: &FheUint16, modval: u16) -> FheUint16 {
    // Fast exponentiation of FheUint16 with FheUint16 exponent
    // NOTE: assumes that the multiplications do not overflow the bitwidth of the FheUint
    // NOTE: assumes that exp != 0, or else we need to return FHE(1) but public key is required
    let mut result = base_enc.clone();
    let mut base_accum = base_enc.clone();
    let mut exp_enc = exp_enc - 1;

    for _i in 0..16 {
        let is_even = (&exp_enc & 1).eq(1);
        let result_if_even = (&result * &base_accum) % modval;
        result = is_even.if_then_else(&result_if_even, &result);
        base_accum = (&base_accum * &base_accum) % modval;
        exp_enc >>= 1u16;
    }
    result
}

// Test fast exponentiation
#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::set_server_key;

    #[test]
    fn test_fhe_exp() {
        let (client_key, server_key, __) = init_keys();
        set_server_key(server_key);
        let clear_a = 3u16;
        let a = FheUint16::encrypt(clear_a, &client_key);
        let a = &a;
        let exp = 10u16;
        // tests both naive and fast implementations
        let result_fast = fhe_exp_16(a, exp);
        let result_naive = fhe_exp_16_naive(a, exp);
        let decrypted_fast: u16 = result_fast.decrypt(&client_key);
        let decrypted_naive: u16 = result_naive.decrypt(&client_key);
        let clear_result: u16 = clear_a.pow(exp as u32);
        assert_eq!(decrypted_naive, clear_result);
        assert_eq!(decrypted_fast, clear_result);
    }

    #[test]
    fn test_fhe_modexp() {
        let (client_key, server_key, __) = init_keys();
        set_server_key(server_key);
        let base = 3u16;
        let exp = 10u16;
        let base_enc = FheUint16::encrypt(base, &client_key);
        let result = fhe_exp_16(&base_enc, exp);
        let decrypted: u16 = result.decrypt(&client_key);
        let clear_result: u16 = base.pow(exp as u32);
        assert_eq!(decrypted, clear_result);
    }

    #[test]
    fn test_fhe2_modexp() {
        let (client_key, server_key, __) = init_keys();
        set_server_key(server_key);
        let base = 3u16;
        let exp = 10u16;
        let modval = 101u16;
        let base_enc = FheUint16::encrypt(base, &client_key);
        let exp_enc = FheUint16::encrypt(exp, &client_key);
        let result = fhe2_modexp_16(&base_enc, &exp_enc, modval);
        let decrypted: u16 = result.decrypt(&client_key);
        let clear_result: u16 = base.pow(exp as u32) % modval;
        assert_eq!(decrypted, clear_result);
    }

    #[test]
    fn test_fhe2_exp_toy() {
        let (client_key, server_key, public_key) = init_keys();
        set_server_key(server_key);

        let base = 3u16;
        let exp: u16 = 10u16;

        let base_enc = FheUint16::encrypt(base, &public_key);
        let exp_enc = FheUint16::encrypt(exp, &public_key);
        let one_enc = FheUint16::encrypt(1u16, &public_key);

        let mut result = one_enc.clone();
        let mut base_accum = base_enc.clone();
        let mut exp_enc = exp_enc.clone();

        for _i in 0..16 {
            let is_even = (&exp_enc & 1).eq(1);
            let result_if_even = &result * &base_accum;
            result = is_even.if_then_else(&result_if_even, &result);
            base_accum = &base_accum * &base_accum;
            exp_enc >>= 1u16;
        }

        // Now result should be the result of the exponentiation
        let decrypted_result: u16 = result.decrypt(&client_key);
        let clear_result: u16 = base.pow(exp as u32);
        assert_eq!(decrypted_result, clear_result);
    }

    #[test]
    fn test_fhe2_modexp_toy() {
        let (client_key, server_key, public_key) = init_keys();
        set_server_key(server_key);

        let base = 3u16;
        let exp: u16 = 10u16;
        let modval = 101u16;

        let base_enc = FheUint16::encrypt(base, &public_key);
        let exp_enc = FheUint16::encrypt(exp, &public_key);
        let one_enc = FheUint16::encrypt(1u16, &public_key);

        let mut result = one_enc.clone();
        let mut base_accum = base_enc.clone();
        let mut exp_enc = exp_enc.clone();

        for _i in 0..16 {
            let is_even = (&exp_enc & 1).eq(1);
            let result_if_even = (&result * &base_accum) % modval;
            result = is_even.if_then_else(&result_if_even, &result);
            base_accum = (&base_accum * &base_accum) % modval;
            exp_enc >>= 1u16;
        }

        // Now result should be the result of the exponentiation
        let decrypted_result: u16 = result.decrypt(&client_key);
        let clear_result: u16 = base.pow(exp as u32) % modval;
        assert_eq!(decrypted_result, clear_result);
    }

    #[test]
    fn test_fhe2_modexp_toy_noenc1() {
        let (client_key, server_key, public_key) = init_keys();
        set_server_key(server_key);

        let base = 3u16;
        let exp: u16 = 10u16;
        let modval = 101u16;

        let base_enc = FheUint16::encrypt(base, &public_key);
        let exp_enc = FheUint16::encrypt(exp, &public_key);

        let mut result = base_enc.clone();
        let mut base_accum = base_enc.clone();
        let mut exp_enc = exp_enc - 1;

        for _i in 0..16 {
            let is_even = (&exp_enc & 1).eq(1);
            let result_if_even = (&result * &base_accum) % modval;
            result = is_even.if_then_else(&result_if_even, &result);
            base_accum = (&base_accum * &base_accum) % modval;
            exp_enc >>= 1u16;
        }

        // Now result should be the result of the exponentiation
        let decrypted_result: u16 = result.decrypt(&client_key);
        let clear_result: u16 = base.pow(exp as u32) % modval;
        assert_eq!(decrypted_result, clear_result);
    }
}
