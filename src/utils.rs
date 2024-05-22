extern crate chrono;
use chrono::Local;

use tfhe::prelude::*;
use tfhe::{
    generate_keys, ClientKey, CompactPublicKey, ConfigBuilder, FheUint128, FheUint16, FheUint32,
    FheUint64, ServerKey,
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


pub fn fhe_exp_64_mod(base: &FheUint64, exp: u64, modval: u64) -> FheUint64 {
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

// Test fast exponentiation
#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::set_server_key;

    #[test]
    fn test_fhe_exp() {
        let (client_key, server_key, __) = init_keys();
        let clear_a = 2u16;
        set_server_key(server_key);
        let a = FheUint16::encrypt(clear_a, &client_key);
        let a = &a;
        let exp = 10u16;
        let result_fast = fhe_exp_16(a, exp);
        let result_naive = fhe_exp_16_naive(a, exp);
        let decrypted_fast: u16 = result_fast.decrypt(&client_key);
        let decrypted_naive: u16 = result_naive.decrypt(&client_key);
        let clear_result: u16 = clear_a.pow(exp as u32);
        assert_eq!(decrypted_naive, clear_result);
        assert_eq!(decrypted_fast, clear_result);
    }
}
