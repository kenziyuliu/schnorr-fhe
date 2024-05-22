extern crate chrono;
use chrono::Local;
use num_bigint::BigUint;

use tfhe::integer::bigint::u256::U256;
use tfhe::prelude::*;
use tfhe::{set_server_key, FheUint256, FheUint64, FheUint32, FheUint16};

// mod utils;

extern crate schnorr_fhe;

use schnorr_fhe::utils;

// Test that we can add a FheUint with a clear
#[test]
fn test_clear_addition() {
    let (client_key, server_key, public_key) = utils::init_keys();

    let clear_a = 1344u32;
    let clear_b = 5u32;
    let clear_c = 7u32;

    let a = FheUint32::encrypt(clear_a, &client_key);
    let b = FheUint32::encrypt(clear_b, &public_key);

    //Server-side
    set_server_key(server_key);
    let result_client = &a + clear_c;
    let result_public = &b + clear_c;

    //Client-side
    let decrypted_client: u32 = result_client.decrypt(&client_key);
    let decrypted_public: u32 = result_public.decrypt(&client_key);

    assert_eq!(decrypted_client, clear_a + clear_c);
    assert_eq!(decrypted_public, clear_b + clear_c);
}

// Test that we can multiply a FheUint with a clear
#[test]
fn test_clear_multiplication() {
    let (client_key, server_key, public_key) = utils::init_keys();

    let clear_a = 1344u32;
    let clear_b = 5u32;
    let clear_c = 7u32;

    let a = FheUint32::encrypt(clear_a, &client_key);
    let b = FheUint32::encrypt(clear_b, &public_key);

    //Server-side
    set_server_key(server_key);
    let result_client = &a * clear_c;
    let result_public = &b * clear_c;

    //Client-side
    let decrypted_client: u32 = result_client.decrypt(&client_key);
    let decrypted_public: u32 = result_public.decrypt(&client_key);

    assert_eq!(decrypted_client, clear_a * clear_c);
    assert_eq!(decrypted_public, clear_b * clear_c);
}

// Test that we can mod a FheUint with a clear
#[test]
fn test_clear_mod() {
    let (client_key, server_key, public_key) = utils::init_keys();

    let clear_a = 1344u32;
    let clear_b = 4050919841u32;
    let clear_c = 7u32;

    let a = FheUint32::encrypt(clear_a, &client_key);
    let b = FheUint32::encrypt(clear_b, &public_key);

    //Server-side
    set_server_key(server_key);
    let result_client = &a % clear_c;
    let result_public = &b % clear_c;

    //Client-side
    let decrypted_client: u32 = result_client.decrypt(&client_key);
    let decrypted_public: u32 = result_public.decrypt(&client_key);

    assert_eq!(decrypted_client, clear_a % clear_c);
    assert_eq!(decrypted_public, clear_b % clear_c);
}

// Test that we can cast an array of FheUint32 to an array of FheUint16 and FheUint64
#[test]
fn test_casting() {
    let (client_key, server_key, public_key) = utils::init_keys();
    set_server_key(server_key);

    let clear_a = 1344u32;
    let clear_b = 5u32;

    let a = FheUint32::encrypt(clear_a, &client_key);
    let b = FheUint32::encrypt(clear_b, &public_key);

    let arr = vec![&a, &b];
    let cast_16: Vec<FheUint16> = arr.iter().map(|x| (*x).clone().cast_into()).collect();
    let cast_64: Vec<FheUint64> = arr.iter().map(|x| (*x).clone().cast_into()).collect();

    let decrypted_16: Vec<u16> = cast_16.iter().map(|x| x.decrypt(&client_key)).collect();
    let decrypted_64: Vec<u64> = cast_64.iter().map(|x| x.decrypt(&client_key)).collect();

    assert_eq!(decrypted_16, vec![clear_a as u16, clear_b as u16]);
    assert_eq!(decrypted_64, vec![clear_a as u64, clear_b as u64]);
}


// Test modification of array elements each being a FheUint
#[test]
fn test_array_modification() {
    let (client_key, server_key, public_key) = utils::init_keys();
    set_server_key(server_key);

    let clear_a = 1344u16;
    let clear_b = 5u16;
    let clear_c = 7u16;

    let a = FheUint16::encrypt(clear_a, &client_key);
    let b = FheUint16::encrypt(clear_b, &public_key);
    let mut arr = vec![&a, &b];

    let test0 = arr[0] + clear_c;
    let test1 = arr[1] * clear_c;
    arr[0] = &test0;
    arr[1] = &test1;
    let decrypted: Vec<u16> = arr.iter().map(|x| x.decrypt(&client_key)).collect();
    assert_eq!(decrypted, vec![clear_a + clear_c, clear_b * clear_c]);

    // The non-reference version
    let a = FheUint16::encrypt(clear_a, &client_key);
    let b = FheUint16::encrypt(clear_b, &public_key);
    let mut arr = vec![a, b];

    // arr[0] = test0;
    arr[0] = &arr[0] + clear_c;
    arr[1] = &arr[1] * clear_c;
    let decrypted: Vec<u16> = arr.iter().map(|x| x.decrypt(&client_key)).collect();
    assert_eq!(decrypted, vec![clear_a + clear_c, clear_b * clear_c]);
}


// // Test that we can add, multiply, and mod a FheUint with a BigUint
// // NOTE: commenting out since this is taking long to run (> 60s)
// #[test]
// fn test_biguint_operations() {
//     let (client_key, server_key, public_key) = utils::init_keys();

//     let clear_a = U256::from(1344u32);
//     let clear_b = U256::from(5u32);
//     let clear_c = U256::from(7u32);

//     let a = FheUint256::encrypt(clear_a, &client_key);
//     let b = FheUint256::encrypt(clear_b, &public_key);

//     // Server-side
//     set_server_key(server_key);
//     let result_client = &a + clear_c;
//     let result_public = &b + clear_c;

//     // Client-side
//     let decrypted_client: U256 = result_client.decrypt(&client_key);
//     let decrypted_public: U256 = result_public.decrypt(&client_key);

//     assert_eq!(decrypted_client, clear_a + clear_c);
//     assert_eq!(decrypted_public, clear_b + clear_c);

//     // Server-side
//     let result_client = &a * clear_c;
//     let result_public = &b * clear_c;

//     //Client-side
//     let decrypted_client: U256 = result_client.decrypt(&client_key);
//     let decrypted_public: U256 = result_public.decrypt(&client_key);

//     assert_eq!(decrypted_client, clear_a * clear_c);
//     assert_eq!(decrypted_public, clear_b * clear_c);

//     //Server-side
//     let result_client = &a % clear_c;
//     let result_public = &b % clear_c;

//     //Client-side
//     let decrypted_client: U256 = result_client.decrypt(&client_key);
//     let decrypted_public: U256 = result_public.decrypt(&client_key);

//     assert_eq!(decrypted_client, clear_a % clear_c);
//     assert_eq!(decrypted_public, clear_b % clear_c);
// }
