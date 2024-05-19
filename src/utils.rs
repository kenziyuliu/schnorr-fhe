extern crate chrono;
use chrono::Local;

use tfhe::{ConfigBuilder, set_server_key, FheUint128, ClientKey, CompressedServerKey, PublicKey, CompactPublicKey}; // 128-bit
use tfhe::prelude::*;


pub fn say_hello() {
    println!("Hello from utils!");
}

// Log a message with the current time
pub fn log(msg: &str) {
    let now = Local::now();
    println!("{now} {msg}");
}


// Naive exponentiation of a FheUint
pub fn fhe_exp(base: &FheUint128, exp: u128) -> FheUint128 {
    let mut result = base.clone();
    for _ in 1..exp {
        result = result * base.clone();
    }
    result
}

// Fast exponentiation of a FheUint
pub fn fhe_exp_fast(base: &FheUint128, exp: u128) -> FheUint128 {
    let mut result = base.clone();
    let mut exp = exp;
    let mut base = base.clone();
    while exp > 1 {
        if exp % 2 == 0 {
            base = base * base;
            exp = exp / 2;
        } else {
            result = result * base.clone();
            exp = exp - 1;
        }
    }
    result
}