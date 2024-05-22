extern crate chrono;
use chrono::Local;
use num_bigint::BigUint;

use tfhe::integer::bigint::u256::U256;
use tfhe::prelude::*;
use tfhe::{set_server_key, FheUint128, FheUint16, FheUint256, FheUint32, FheUint64};

// mod utils;

extern crate schnorr_fhe;

use schnorr_fhe::utils;

// Benchmark the time taken to perform addition, multiplication, and mod operations on FheUints
#[test]
fn benchmark_32() {
    let (client_key, server_key, public_key) = utils::init_keys();
    set_server_key(server_key);

    let clear_a = 1344u32;
    let clear_b = 5u32;
    let clear_c = 7u32;

    let a = FheUint32::encrypt(clear_a, &client_key);
    let b = FheUint32::encrypt(clear_b, &public_key);

    // Addition: FheUint + clear
    let t_start = Local::now();
    let _result_client = &a + clear_c;
    let t_end = Local::now();
    println!(
        "Client add (fhe + clear) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    let t_start = Local::now();
    let _result_public = &b + clear_c;
    let t_end = Local::now();
    println!(
        "Public add (fhe + clear) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    // Addition: FheUint + FheUint
    let t_start = Local::now();
    let _result_client = &a + &a;
    let t_end = Local::now();
    println!(
        "Client add (fhe + fhe) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    let t_start = Local::now();
    let _result_public = &b + &b;
    let t_end = Local::now();
    println!(
        "Public add (fhe + fhe) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    // Multiplication: FheUint * clear
    let t_start = Local::now();
    let _result_client = &a * clear_c;
    let t_end = Local::now();
    println!(
        "Client mult (fhe * clear) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    let t_start = Local::now();
    let _result_public = &b * clear_c;
    let t_end = Local::now();
    println!(
        "Public mult (fhe * clear) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    // Multiplication: FheUint * FheUint
    let t_start = Local::now();
    let _result_client = &a * &a;
    let t_end = Local::now();
    println!(
        "Client mult (fhe * fhe) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    let t_start = Local::now();
    let _result_public = &b * &b;
    let t_end = Local::now();
    println!(
        "Public mult (fhe * fhe) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    // Modulus: FheUint % clear
    let t_start = Local::now();
    let _result_client = &a % clear_c;
    let t_end = Local::now();
    println!(
        "Client mod (fhe % clear) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    let t_start = Local::now();
    let _result_public = &b % clear_c;
    let t_end = Local::now();
    println!(
        "Public mod (fhe % clear) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    // Modulus: FheUint % FheUint
    let t_start = Local::now();
    let _result_client = &a % &a;
    let t_end = Local::now();
    println!(
        "Client mod (fhe % fhe) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    let t_start = Local::now();
    let _result_public = &b % &b;
    let t_end = Local::now();
    println!(
        "Public mod (fhe % fhe) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );
}


#[test]
fn benchmark_16() {
    let (client_key, server_key, public_key) = utils::init_keys();
    set_server_key(server_key);

    let clear_a = 1344u16;
    let clear_b = 5u16;
    let clear_c = 7u16;

    let a = FheUint16::encrypt(clear_a, &client_key);
    let b = FheUint16::encrypt(clear_b, &public_key);

    // Addition: FheUint + clear
    let t_start = Local::now();
    let _result_client = &a + clear_c;
    let t_end = Local::now();
    println!(
        "Client add (fhe + clear) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    let t_start = Local::now();
    let _result_public = &b + clear_c;
    let t_end = Local::now();
    println!(
        "Public add (fhe + clear) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    // Addition: FheUint + FheUint
    let t_start = Local::now();
    let _result_client = &a + &a;
    let t_end = Local::now();
    println!(
        "Client add (fhe + fhe) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    let t_start = Local::now();
    let _result_public = &b + &b;
    let t_end = Local::now();
    println!(
        "Public add (fhe + fhe) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    // Multiplication: FheUint * clear
    let t_start = Local::now();
    let _result_client = &a * clear_c;
    let t_end = Local::now();
    println!(
        "Client mult (fhe * clear) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    let t_start = Local::now();
    let _result_public = &b * clear_c;
    let t_end = Local::now();
    println!(
        "Public mult (fhe * clear) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    // Multiplication: FheUint * FheUint
    let t_start = Local::now();
    let _result_client = &a * &a;
    let t_end = Local::now();
    println!(
        "Client mult (fhe * fhe) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    let t_start = Local::now();
    let _result_public = &b * &b;
    let t_end = Local::now();
    println!(
        "Public mult (fhe * fhe) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    // Modulus: FheUint % clear
    let t_start = Local::now();
    let _result_client = &a % clear_c;
    let t_end = Local::now();
    println!(
        "Client mod (fhe % clear) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    let t_start = Local::now();
    let _result_public = &b % clear_c;
    let t_end = Local::now();
    println!(
        "Public mod (fhe % clear) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    // Modulus: FheUint % FheUint
    let t_start = Local::now();
    let _result_client = &a % &a;
    let t_end = Local::now();
    println!(
        "Client mod (fhe % fhe) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    let t_start = Local::now();
    let _result_public = &b % &b;
    let t_end = Local::now();
    println!(
        "Public mod (fhe % fhe) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );
}


#[test]
fn benchmark_64() {
    let (client_key, server_key, public_key) = utils::init_keys();
    set_server_key(server_key);

    let clear_a = 1344u64;
    let clear_b = 5u64;
    let clear_c = 7u64;

    let a = FheUint64::encrypt(clear_a, &client_key);
    let b = FheUint64::encrypt(clear_b, &public_key);

    // Addition: FheUint + clear
    let t_start = Local::now();
    let _result_client = &a + clear_c;
    let t_end = Local::now();
    println!(
        "Client add (fhe + clear) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    let t_start = Local::now();
    let _result_public = &b + clear_c;
    let t_end = Local::now();
    println!(
        "Public add (fhe + clear) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    // Addition: FheUint + FheUint
    let t_start = Local::now();
    let _result_client = &a + &a;
    let t_end = Local::now();
    println!(
        "Client add (fhe + fhe) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    let t_start = Local::now();
    let _result_public = &b + &b;
    let t_end = Local::now();
    println!(
        "Public add (fhe + fhe) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    // Multiplication: FheUint * clear
    let t_start = Local::now();
    let _result_client = &a * clear_c;
    let t_end = Local::now();
    println!(
        "Client mult (fhe * clear) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    let t_start = Local::now();
    let _result_public = &b * clear_c;
    let t_end = Local::now();
    println!(
        "Public mult (fhe * clear) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    // Multiplication: FheUint * FheUint
    let t_start = Local::now();
    let _result_client = &a * &a;
    let t_end = Local::now();
    println!(
        "Client mult (fhe * fhe) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    let t_start = Local::now();
    let _result_public = &b * &b;
    let t_end = Local::now();
    println!(
        "Public mult (fhe * fhe) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    // Modulus: FheUint % clear
    let t_start = Local::now();
    let _result_client = &a % clear_c;
    let t_end = Local::now();
    println!(
        "Client mod (fhe % clear) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    let t_start = Local::now();
    let _result_public = &b % clear_c;
    let t_end = Local::now();
    println!(
        "Public mod (fhe % clear) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    // Modulus: FheUint % FheUint
    let t_start = Local::now();
    let _result_client = &a % &a;
    let t_end = Local::now();
    println!(
        "Client mod (fhe % fhe) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );

    let t_start = Local::now();
    let _result_public = &b % &b;
    let t_end = Local::now();
    println!(
        "Public mod (fhe % fhe) took {:?} ms",
        t_end.signed_duration_since(t_start).num_milliseconds()
    );
}
