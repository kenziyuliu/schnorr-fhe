use num::BigUint;
use num_traits::ToPrimitive;
use tfhe::prelude::*;
use tfhe::{FheUint16, FheUint8};

use crate::constants;
use crate::utils;

/* DEBT: This is a copy of the poseidon module from schnorr-fhe/src/poseidon.rs
 * to handle 8-bit primes. This is a temporary solution until we refactor the
 * code to handle any bit-width.
 */

fn apply_mds_matrix_u16(
    inputs: Vec<FheUint16>,
    mds_matrix: &[[u16; constants::POSEIDON_T]; constants::POSEIDON_T],
    prime: u16,
) -> Vec<FheUint16> {
    /* For a t x t MDS matrix, there is:
     * - t inputs and t outputs
     * - t x t multiplications
     * - t x (t-1) additions
     * - t x (2t-1) (mod p) operations
     */
    let mut outputs: Vec<FheUint16> = Vec::new();
    for i in 0..inputs.len() {
        // Since we cannot initialize an FheUint zero without an encryption key
        // we will initialize the output as the first multiplication
        let mut output: FheUint16 = &(&inputs[0] * mds_matrix[i][0]) % prime;
        for j in 1..inputs.len() {
            let mult = &(&inputs[j] * mds_matrix[i][j]) % prime;
            output = &(&output + &mult) % prime;
        }
        outputs.push(output);
    }
    outputs
}

fn apply_mds_matrix_biguint(
    inputs: Vec<BigUint>,
    mds_matrix: &Vec<Vec<BigUint>>,
    prime: &BigUint,
) -> Vec<BigUint> {
    let mut outputs: Vec<BigUint> = Vec::new();
    for i in 0..inputs.len() {
        let mut output: BigUint = BigUint::from(0u8);
        for j in 0..inputs.len() {
            let mult = &(&inputs[j] * &mds_matrix[i][j]) % prime;
            output = &(&output + &mult) % prime;
        }
        outputs.push(output);
    }
    outputs
}

fn pick_round_constants_p8(r_full: usize, r_partial: usize) -> Vec<u16> {
    // Pick the round constants based on the number of full and partial rounds
    if r_full == 2 && r_partial == 1 {
        T4_P8_RC_R1_TEST.to_vec()
    } else {
        T4_P8_RC.to_vec()
    }
}

pub fn poseidon_p8_rf2_rp1(inputs: [&FheUint8; constants::POSEIDON_T]) -> FheUint8 {
    poseidon_p8_impl(inputs, 2, 1)
}

pub fn poseidon_p8(inputs: [&FheUint8; constants::POSEIDON_T]) -> FheUint8 {
    poseidon_p8_impl(
        inputs,
        constants::POSEIDON_R_FULL,
        constants::POSEIDON_R_PARTIAL,
    )
}

pub fn poseidon_p8_impl(
    inputs: [&FheUint8; constants::POSEIDON_T],
    r_full: usize,
    r_partial: usize,
) -> FheUint8 {
    let rc_list = pick_round_constants_p8(r_full, r_partial);
    assert_eq!(rc_list.len(), (r_full + r_partial) * constants::POSEIDON_T);
    // Check r_full is even
    assert_eq!(r_full % 2, 0);

    // Apply mod prime to all inputs (refs in, values out)
    // Note that we dont yet need to move up bit-width since inputs must fit in
    // 8-bit uints and the prime is 8-bit; i.e., no overflow just to do mod.
    let inputs: Vec<FheUint8> = inputs
        .iter()
        .map(|x| (*x) % constants::POSEIDON_P_8)
        .collect();

    // NOTE: Handling modular addition and multiplication overflow.
    // Observe that with a 8-bit prime and 8-bit integers:
    // - (a + b) % p != (a % p + b % p) % p since the sum can overflow the int type
    //   e.g. a = b = 3, p = 3, 2-bit integers so n=4
    //   (3 + 3) % 2^2 % 3 = 2, but (3 % 3 + 3 % 3) % 3 = 0
    // - (a * b) % p != (a % p * b % p) % p since the product can overflow too
    // To handle overflow, we will use a larger type for the intermediate operations
    // and then cast down the results before returning.
    // Now convert the inputs to FheUint16.
    let p8_16 = constants::POSEIDON_P_8 as u16;
    let mut inputs_16: Vec<FheUint16> = inputs.iter().map(|x| x.clone().cast_into()).collect();
    let mut rc_counter: usize = 0;

    // Full rounds: first half
    for _i in 0..r_full / 2 {
        for j in 0..inputs.len() {
            // 1. Add round constants
            // inner &: addition of FheUint16 and u16; outer &: mod p8_16
            let new_val = &(&inputs_16[j] + rc_list[rc_counter]) % p8_16;
            rc_counter += 1;

            // 2. Apply S-Box
            let new_val = utils::fhe_modexp_16(&new_val, constants::POSEIDON_ALPHA as u16, p8_16);
            inputs_16[j] = new_val;
        }
        // 3. Apply MDS matrix
        inputs_16 = apply_mds_matrix_u16(inputs_16, &T4_P8_MDS_MATRIX, p8_16);
    }

    // Partial rounds
    for _i in 0..r_partial {
        for j in 0..inputs.len() {
            // 1. Add round constants
            let new_val = &(&inputs_16[j] + rc_list[rc_counter]) % p8_16;
            inputs_16[j] = new_val;
            rc_counter += 1;
        }
        // 2. Apply S-Box
        inputs_16[0] = utils::fhe_modexp_16(&inputs_16[0], constants::POSEIDON_ALPHA as u16, p8_16);
        // 3. Apply MDS matrix
        inputs_16 = apply_mds_matrix_u16(inputs_16, &T4_P8_MDS_MATRIX, p8_16);
    }

    // Full rounds: second half
    for _i in 0..r_full / 2 {
        for j in 0..inputs.len() {
            // 1. Add round constants
            // inner &: addition of FheUint16 and u16; outer &: mod p8_16
            let new_val = &(&inputs_16[j] + rc_list[rc_counter]) % p8_16;
            rc_counter += 1;

            // 2. Apply S-Box
            let new_val = utils::fhe_modexp_16(&new_val, constants::POSEIDON_ALPHA as u16, p8_16);
            inputs_16[j] = new_val;
        }
        // 3. Apply MDS matrix
        inputs_16 = apply_mds_matrix_u16(inputs_16, &T4_P8_MDS_MATRIX, p8_16);
    }

    // Return the first element
    let hash: FheUint8 = inputs_16[1].clone().cast_into();
    hash
}

/*
 * Same as `poseidon_p8_impl` but operates in the clear. Make use of
 * linear algebra optimizations for the MDS matrix multiplication.
 *
 * Note that while the logic applies to any unsigned integer type (due to the
 * use of BigUint), the make use of the MDS matrix / round constants that
 * are specific to 8-bit.
 *
 * TODO: In future refactoring, we can implement a generic version that
 * can handle any bit-width.
 */

pub fn poseidon_p8_clear_rf2_rp1(inputs: [u8; constants::POSEIDON_T]) -> u8 {
    poseidon_p8_clear_impl(inputs, 2, 1)
}

pub fn poseidon_p8_clear(inputs: [u8; constants::POSEIDON_T]) -> u8 {
    poseidon_p8_clear_impl(
        inputs,
        constants::POSEIDON_R_FULL,
        constants::POSEIDON_R_PARTIAL,
    )
}

pub fn poseidon_p8_clear_impl(
    inputs: [u8; constants::POSEIDON_T],
    r_full: usize,
    r_partial: usize,
) -> u8 {
    let rc_list = pick_round_constants_p8(r_full, r_partial);
    assert_eq!(rc_list.len(), (r_full + r_partial) * constants::POSEIDON_T);
    assert_eq!(r_full % 2, 0);

    // Apply mod prime to all inputs (refs in, values out)
    // Note that we dont yet need to move up bit-width since inputs must fit in
    // 8-bit uints and the prime is 8-bit; i.e., no overflow just to do mod.
    let inputs: Vec<u8> = inputs.iter().map(|x| x % constants::POSEIDON_P_8).collect();

    // NOTE: Handling modular addition and multiplication overflow.
    // To handle overflow, we will use a larger type for the intermediate operations
    // and then cast down the results before returning.
    // Now convert the inputs to FheUint16.
    let p_big = BigUint::from(constants::POSEIDON_P_8);
    let alpha = BigUint::from(constants::POSEIDON_ALPHA);
    let mut inputs: Vec<BigUint> = inputs.iter().map(|x| BigUint::from(*x)).collect();
    let mut rc_counter: usize = 0;
    let mds_matrix = T4_P8_MDS_MATRIX
        .iter()
        .map(|x| x.iter().map(|y| BigUint::from(*y)).collect())
        .collect::<Vec<Vec<BigUint>>>();

    // Full rounds: first half
    for _i in 0..r_full / 2 {
        for j in 0..inputs.len() {
            // 1. Add round constants
            // inner &: addition of FheUint16 and u16; outer &: mod p_big
            let new_val = &(&inputs[j] + rc_list[rc_counter]) % &p_big;
            rc_counter += 1;
            // 2. Apply S-Box
            inputs[j] = new_val.modpow(&alpha, &p_big);
        }
        // 3. Apply MDS matrix
        // NOTE: since matrix is small, we can do the multiplication directly
        inputs = apply_mds_matrix_biguint(inputs, &mds_matrix, &p_big);
    }

    // Partial rounds
    for _i in 0..r_partial {
        for j in 0..inputs.len() {
            // 1. Add round constants
            inputs[j] = &(&inputs[j] + rc_list[rc_counter]) % &p_big;
            rc_counter += 1;
        }
        // 2. Apply S-Box
        inputs[0] = inputs[0].modpow(&alpha, &p_big);
        // 3. Apply MDS matrix
        inputs = apply_mds_matrix_biguint(inputs, &mds_matrix, &p_big);
    }

    // Full rounds: second half
    for _i in 0..r_full / 2 {
        for j in 0..inputs.len() {
            // 1. Add round constants
            // inner &: addition of FheUint16 and u16; outer &: mod p_big
            let new_val = &(&inputs[j] + rc_list[rc_counter]) % &p_big;
            rc_counter += 1;
            // 2. Apply S-Box
            inputs[j] = new_val.modpow(&alpha, &p_big);
        }
        // 3. Apply MDS matrix
        // NOTE: since matrix is small, we can do the multiplication directly
        inputs = apply_mds_matrix_biguint(inputs, &mds_matrix, &p_big);
    }

    // Return the first element
    let hash: u8 = inputs[1].to_u8().expect("Failed to convert to u8");
    hash
}

////////////////////////////// Poseidon constants //////////////////////////////

/*
 *  Poseidon constants for t4_p8 (non-optimized version)
 *  To reproduce:
 *  1. Clone https://github.com/ingonyama-zk/poseidon-hash
 *  2. Initialize the hash instance as follows:
 *  ```
 *  from poseidon import Poseidon
 *  p8 = 199
 *  H8 = Poseidon(p=p8, security_level=8, alpha=5,
 *                 input_rate=None, t=4, full_round=8, partial_round=56)
 *  ```
 *  3. For round constants: read `np.array(list(map(int, H8.rc_field)))`
 *  4. For MDS matrix: read `H8.mds_matrix`
 */

// number of round constants
const T4_P8_NUM_RC: usize =
    (constants::POSEIDON_R_FULL + constants::POSEIDON_R_PARTIAL) * constants::POSEIDON_T as usize;

// Round constants; all values are mod POSEIDON_P_8
// NOTE: that we use u16 since modular addition can overflow u8
const T4_P8_RC: [u16; T4_P8_NUM_RC] = [
    36, 84, 41, 31, 185, 109, 188, 195, 100, 80, 90, 98, 173, 121, 112, 131, 42, 53, 86, 188, 52,
    152, 25, 41, 42, 46, 176, 27, 184, 65, 181, 132, 136, 4, 93, 46, 10, 187, 179, 6, 99, 0, 167,
    149, 26, 84, 31, 169, 155, 30, 166, 3, 39, 173, 137, 178, 170, 149, 179, 61, 122, 123, 129, 16,
    144, 37, 97, 94, 168, 37, 186, 146, 85, 50, 187, 4, 124, 44, 75, 127, 76, 68, 53, 135, 10, 36,
    46, 50, 139, 135, 80, 33, 44, 92, 114, 53, 69, 169, 117, 95, 45, 51, 40, 129, 54, 161, 150,
    176, 155, 85, 76, 57, 120, 172, 133, 44, 104, 40, 172, 41, 118, 99, 99, 128, 0, 102, 63, 79,
    11, 140, 145, 24, 119, 113, 118, 119, 167, 62, 165, 133, 132, 26, 116, 188, 62, 66, 186, 30,
    33, 108, 74, 84, 19, 174, 158, 67, 188, 119, 94, 151, 112, 126, 41, 58, 184, 184, 97, 140, 6,
    123, 112, 168, 15, 14, 168, 30, 10, 151, 29, 189, 81, 171, 31, 198, 193, 17, 99, 195, 178, 157,
    171, 167, 156, 2, 140, 0, 19, 150, 58, 86, 89, 191, 124, 60, 149, 147, 144, 159, 89, 82, 179,
    190, 75, 111, 141, 4, 143, 170, 16, 57, 52, 101, 106, 58, 134, 102, 165, 37, 60, 190, 97, 109,
    138, 147, 16, 96, 38, 48, 144, 117, 159, 150, 112, 103, 37, 48, 176, 116, 64, 0, 164, 60, 1,
    51, 48, 160,
];

// t x t MDS matrix; all values are mod POSEIDON_P_8
// NOTE: we use u16 since modular multiplication can overflow u8
const T4_P8_MDS_MATRIX: [[u16; constants::POSEIDON_T]; constants::POSEIDON_T] = [
    [50, 40, 166, 57],
    [40, 166, 57, 25],
    [166, 57, 25, 177],
    [57, 25, 177, 20],
];

// Round constants for t4_p32 but r_full = 2, r_partial = 1 (for testing purposes)
const T4_P8_RC_R1_TEST: [u16; 12] = [99, 97, 197, 119, 124, 43, 21, 146, 191, 195, 82, 71];

///////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// Tests ////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

// Test MDS matrix multiplication with T4_P8_MDS_MATRIX
#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::set_server_key;

    // Test FHE matrix multiplication
    #[test]
    fn test_apply_mds_matrix_u16() {
        let (client_key, server_key, _public_key) = utils::init_keys();
        set_server_key(server_key);

        // Inputs
        let inputs: Vec<FheUint16> = vec![
            FheUint16::encrypt(1u16, &client_key),
            FheUint16::encrypt(0u16, &client_key),
            FheUint16::encrypt(2u16, &client_key),
            FheUint16::encrypt(8u16, &client_key),
        ];
        let output =
            apply_mds_matrix_u16(inputs, &T4_P8_MDS_MATRIX, constants::POSEIDON_P_8 as u16);
        let output: Vec<u16> = output.iter().map(|x| x.decrypt(&client_key)).collect();

        // Print output
        println!("{:?}", output);

        // Expected output based on T4_P8_MDS_MATRIX @ [1, 0, 2, 8]
        // To reproduce:
        // ```
        // from poseidon import Poseidon
        // p8 = 199
        // H8 = Poseidon(p=p8, security_level=8, alpha=5,
        //                input_rate=None, t=4, full_round=8, partial_round=56)
        // H8.mds_matrix @ H8.field_p([1,0,2,8])
        // ```
        let expected: Vec<u16> = vec![42, 155, 40, 173];

        // Check
        assert_eq!(output, expected);
    }

    // Test Poseidon end-to-end
    #[test]
    fn test_poseidon_p8_full() {
        let (client_key, server_key, _public_key) = utils::init_keys();
        set_server_key(server_key);

        // Inputs
        let inputs: [&FheUint8; constants::POSEIDON_T] = [
            &FheUint8::encrypt(1u8, &client_key),
            &FheUint8::encrypt(0u8, &client_key),
            &FheUint8::encrypt(2u8, &client_key),
            &FheUint8::encrypt(8u8, &client_key),
        ];
        let output = poseidon_p8(inputs);
        let output: u8 = output.decrypt(&client_key);

        // Expected output based on T4_P8_MDS_MATRIX @ [1, 0, 2, 8]
        // To reproduce:
        // ```
        // from poseidon import Poseidon
        // p8 = 199
        // H8 = Poseidon(p=p8, security_level=8, alpha=5, input_rate=None,
        //                t=4, full_round=8, partial_round=56)
        // H8.run_hash([1,0,2,8])
        // ```
        let expected: u8 = 42;
        assert_eq!(output, expected);
    }

    // Test Poseidon end-to-end, in the clear
    #[test]
    fn test_poseidon_p8_clear_full() {
        // Inputs
        let inputs: [u8; constants::POSEIDON_T] = [1u8, 0u8, 2u8, 8u8];
        let output = poseidon_p8_clear(inputs);
        // see `test_poseidon_p8_full` above for expected result
        let expected: u8 = 42;
        assert_eq!(output, expected);
    }

    // Test Poseidon end-to-end but with r_full = 2, r_partial = 1 for fast testing
    #[test]
    fn test_poseidon_p8_rf2_rp1() {
        let (client_key, server_key, _public_key) = utils::init_keys();
        set_server_key(server_key);

        // Inputs
        let inputs: [&FheUint8; constants::POSEIDON_T] = [
            &FheUint8::encrypt(1u8, &client_key),
            &FheUint8::encrypt(0u8, &client_key),
            &FheUint8::encrypt(2u8, &client_key),
            &FheUint8::encrypt(8u8, &client_key),
        ];
        // let output = poseidon_p8(inputs.iter().collect(), 2, 1);
        let output = poseidon_p8_rf2_rp1(inputs);
        let output: u8 = output.decrypt(&client_key);

        // Expected output based on T4_P8_MDS_MATRIX @ [1, 0, 2, 8]
        // To reproduce:
        // ```
        // from poseidon import Poseidon
        // p8 = 3552575077
        // H8_r1 = Poseidon(p=p8, security_level=8, alpha=5, input_rate=None,
        //                   t=4, full_round=2, partial_round=1)
        // H8_r1.run_hash([1,0,2,8])
        // ```
        let expected: u8 = 13;
        assert_eq!(output, expected);
    }

    #[test]
    fn test_poseidon_p8_clear_rf2_rp1() {
        // Inputs
        let inputs: [u8; constants::POSEIDON_T] = [1u8, 0u8, 2u8, 8u8];
        let output = poseidon_p8_clear_rf2_rp1(inputs);
        // see `test_poseidon_p8_rf2_rp1` above for expected result
        let expected: u8 = 13;
        assert_eq!(output, expected);
    }
}
