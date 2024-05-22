// use ndarray::Array1;
// use ndarray::Array2;
// use phf::phf_map;

// use tfhe::integer::bigint::{u256, u512};
use tfhe::prelude::*;
use tfhe::{generate_keys, FheUint32, FheUint64, FheUint8};
use tfhe::{
    set_server_key, ClientKey, CompactPublicKey, CompressedServerKey, ConfigBuilder, FheUint128,
    PublicKey, ServerKey,
}; // 128-bit

use crate::constants;
use crate::utils;

// An instance of Poseidon following Neptune/File except the prime size is different

fn pick_round_constants_p32(r_full: usize, r_partial: usize) -> Vec<u64> {
    // Pick the round constants based on the number of full and partial rounds
    if r_full == 2 && r_partial == 1 {
        T4_P32_RC_R1_TEST.to_vec()
    } else {
        T4_P32_RC.to_vec()
    }
}

fn apply_mds_matrix(
    inputs: Vec<FheUint64>,
    mds_matrix: &[[u64; constants::POSEIDON_T]; constants::POSEIDON_T],
    prime: u64,
) -> Vec<FheUint64> {
    /* For a t x t MDS matrix, there is:
     * - t inputs and t outputs
     * - t x t multiplications
     * - t x (t-1) additions
     * - t x (2t-1) (mod p) operations
     */
    let mut outputs: Vec<FheUint64> = Vec::new();
    for i in 0..inputs.len() {
        // Since we cannot initialize an FheUint zero without an encryption key
        // we will initialize the output as the first multiplication
        let mut output: FheUint64 = &(&inputs[0] * mds_matrix[i][0]) % prime;
        for j in 1..inputs.len() {
            let mult = &(&inputs[j] * mds_matrix[i][j]) % prime;
            output = &(&output + &mult) % prime;
        }
        outputs.push(output);
    }
    outputs
}

pub fn poseidon_p32(inputs: Vec<&FheUint32>, r_full: usize, r_partial: usize) -> FheUint32 {
    // TODO: depending on the r_full and r_partial, pick the round constants
    let round_consts = pick_round_constants_p32(r_full, r_partial);
    assert_eq!(
        round_consts.len(),
        (r_full + r_partial) * constants::POSEIDON_T
    );
    // Check input length
    assert_eq!(inputs.len(), constants::POSEIDON_T);
    // Check r_full is even
    assert_eq!(r_full % 2, 0);

    // Apply mod prime to all inputs (refs in, values out)
    let inputs: Vec<FheUint32> = inputs
        .iter()
        .map(|x| (*x) % constants::POSEIDON_P_32)
        .collect();

    // NOTE: Handling modular addition and multiplication overflow.
    // Observe that with a 32-bit prime and 32-bit integers:
    // - (a + b) % p != (a % p + b % p) % p since the sum can overflow the int type
    //   e.g. a = b = 3, p = 3, 2-bit integers so n=4
    //   (3 + 3) % 2^2 % 3 = 2, but (3 % 3 + 3 % 3) % 3 = 0
    // - (a * b) % p != (a % p * b % p) % p since the product can overflow too
    // To handle overflow, we will use a larger type for the intermediate operations
    // and then cast down the results before returning.
    // Now convert the inputs to FheUint64.
    let p32_64 = constants::POSEIDON_P_32 as u64;
    let mut inputs_64: Vec<FheUint64> = inputs.iter().map(|x| x.clone().cast_into()).collect();
    let mut rc_counter: usize = 0;

    // Full rounds: first half
    for _i in 0..r_full / 2 {
        for j in 0..inputs.len() {
            // 1. Add round constants
            // inner &: addition of FheUint64 and u64; outer &: mod p32_64
            let new_val = &(&inputs_64[j] + round_consts[rc_counter]) % p32_64;
            rc_counter += 1;

            // 2. Apply S-Box
            let new_val = utils::fhe_exp_64_mod(&new_val, constants::POSEIDON_ALPHA as u64, p32_64);
            inputs_64[j] = new_val;
        }
        // 3. Apply MDS matrix
        inputs_64 = apply_mds_matrix(inputs_64, &T4_P32_MDS_MATRIX, p32_64);
    }

    // Partial rounds
    for _i in 0..r_partial {
        for j in 0..inputs.len() {
            // 1. Add round constants
            let new_val = &(&inputs_64[j] + round_consts[rc_counter]) % p32_64;
            inputs_64[j] = new_val;
            rc_counter += 1;
        }
        // 2. Apply S-Box
        inputs_64[0] =
            utils::fhe_exp_64_mod(&inputs_64[0], constants::POSEIDON_ALPHA as u64, p32_64);
        // 3. Apply MDS matrix
        inputs_64 = apply_mds_matrix(inputs_64, &T4_P32_MDS_MATRIX, p32_64);
    }

    // Full rounds: second half
    for _i in 0..r_full / 2 {
        for j in 0..inputs.len() {
            // 1. Add round constants
            // inner &: addition of FheUint64 and u64; outer &: mod p32_64
            let new_val = &(&inputs_64[j] + round_consts[rc_counter]) % p32_64;
            rc_counter += 1;

            // 2. Apply S-Box
            let new_val = utils::fhe_exp_64_mod(&new_val, constants::POSEIDON_ALPHA as u64, p32_64);
            inputs_64[j] = new_val;
        }
        // 3. Apply MDS matrix
        inputs_64 = apply_mds_matrix(inputs_64, &T4_P32_MDS_MATRIX, p32_64);
    }

    // Return the first element
    let hash: FheUint32 = inputs_64[1].clone().cast_into();
    hash
}

////////////////////////////// Poseidon constants //////////////////////////////

/*
 *  Poseidon constants for t4_p32 (non-optimized version)
 *  To reproduce:
 *  1. Clone https://github.com/ingonyama-zk/poseidon-hash
 *  2. Initialize the hash instance as follows:
 *  ```
 *  from poseidon import Poseidon
 *  p32 = 3552575077
 *  H32 = Poseidon(p=p32, security_level=32, alpha=5,
 *                 input_rate=None, t=4, full_round=8, partial_round=56)
 *  ```
 *  3. For round constants: read `list(map(int, H32.rc_field))`
 *  4. For MDS matrix: read `list(map(int, H32.mds_matrix))`
 */

// number of round constants
const T4_P32_NUM_RC: usize =
    (constants::POSEIDON_R_FULL + constants::POSEIDON_R_PARTIAL) * constants::POSEIDON_T as usize;

// Round constants; all values are mod POSEIDON_P_32
// NOTE: that we use u64 since modular addition can overflow u32
const T4_P32_RC: [u64; T4_P32_NUM_RC] = [
    3099850505, 3179516854, 307261169, 787761466, 2275476481, 2225275640, 2994401083, 3413351842,
    2856083989, 2347979165, 2081881791, 2708334814, 1919447024, 1580658411, 2871370135, 3452225719,
    1860524872, 2426372693, 2773476711, 1197209734, 1683489867, 536884435, 166238553, 3181718636,
    1335754851, 2742560894, 678072798, 3344401184, 531448979, 1001901256, 1883173011, 1232491573,
    259628726, 3394417492, 1974200766, 757644604, 3546461737, 2176114810, 598528939, 1401052157,
    2196221925, 1658390909, 2094386898, 1696412216, 2071415470, 1534493193, 1371199330, 568142009,
    2896067480, 3137296086, 2102493908, 3458122763, 897106465, 3395463776, 1757891339, 207272094,
    2727542899, 1736930361, 1721846043, 1424550870, 1835690357, 2859484434, 1800016633, 201993284,
    215683983, 1411790707, 2147918544, 71092249, 2983489284, 913464423, 2296412015, 3018523490,
    1551338438, 1262172092, 2693140802, 2039628943, 2019583476, 1518118815, 1998491344, 3186331764,
    412356028, 2522393989, 2869212488, 3102263488, 1452955401, 2759353107, 2799741381, 222765041,
    132981644, 2319606456, 1455666007, 990206873, 499274254, 809289575, 1904527150, 1372947389,
    3208968559, 557021055, 3122104659, 730749847, 599365029, 1285233766, 879156767, 2005099873,
    1344736228, 2701406876, 2559773611, 296254486, 1891284223, 1545980222, 112686241, 2791853118,
    1515763600, 473113348, 1746712238, 519530258, 174960741, 769373706, 1963602836, 2377743748,
    2043614120, 1886976780, 2359555624, 1053199492, 1139113946, 1372518430, 569518733, 3535258123,
    1950261949, 587293426, 1075626675, 1938215399, 1378065227, 905030635, 1180767793, 1696981789,
    171311903, 895432029, 1881472565, 339833772, 2561589514, 30114794, 780309098, 393527907,
    144799295, 1462574029, 229593533, 1402728584, 161037413, 2391424361, 699658795, 350293920,
    1414726217, 1378282701, 1496007019, 1146975674, 1642696163, 166381769, 1061088641, 2026851337,
    2141704497, 2372852189, 815695497, 1950508239, 2043891635, 3037972619, 282226641, 1702473415,
    1948589137, 1363890715, 1131235035, 94658236, 73967154, 415132980, 1112536758, 645817235,
    611337531, 2339909382, 3444791587, 2608791387, 1280462839, 2877726904, 166942416, 767180540,
    167908829, 902782698, 2554776308, 117719159, 2400243197, 1657096076, 1132143350, 2125011374,
    2058908206, 366438040, 1962981586, 2297542456, 1536130175, 661118100, 2018119793, 2887242221,
    1271009549, 3338989812, 2679736603, 460707428, 32969198, 1192966470, 3471738875, 180576791,
    278553931, 2146022848, 776646969, 2388486999, 1113963847, 2118933805, 934022812, 1331742939,
    2936585764, 429246239, 192973457, 426973148, 976691946, 2051872635, 717960115, 1491563885,
    2651521991, 2663725801, 1947056952, 176032116, 1827826784, 808072454, 230560935, 438803671,
    1990241738, 544659575, 1495519323, 484404301, 204474905, 787278736, 1283827532, 611165895,
    586166262, 3355599834, 3265570048, 2610811117, 363239904, 2066056234, 1672142417, 2043248489,
    1265189466, 271671167, 318641430, 700587625, 185655075, 345033561, 1107847779, 1966660220,
];

// t x t MDS matrix; all values are mod POSEIDON_P_32
// NOTE: we use u64 since modular multiplication can overflow u32
const T4_P32_MDS_MATRIX: [[u64; constants::POSEIDON_T]; constants::POSEIDON_T] = [
    [2664431308, 1421030031, 2960479231, 1522532176],
    [1421030031, 2960479231, 1522532176, 1332215654],
    [2960479231, 1522532176, 1332215654, 3157844513],
    [1522532176, 1332215654, 3157844513, 2486802554],
];

// Round constants for t4_p32 but r_full = 2, r_partial = 1 (for testing purposes)
const T4_P32_RC_R1_TEST: [u64; 12] = [
    110929376, 2029821953, 1891938406, 2833957075, 1439843622, 1042882281, 3302117744, 1858984797,
    1904202925, 2469559821, 974687881, 937552036,
];

////////////////////////////// Tests //////////////////////////////

// Test MDS matrix multiplication with T4_P32_MDS_MATRIX
#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::set_server_key;

    // Test FHE matrix multiplication
    #[test]
    fn test_apply_mds_matrix() {
        let (client_key, server_key, _public_key) = utils::init_keys();
        set_server_key(server_key);

        // Inputs
        let inputs: Vec<FheUint64> = vec![
            FheUint64::encrypt(1u64, &client_key),
            FheUint64::encrypt(0u64, &client_key),
            FheUint64::encrypt(2u64, &client_key),
            FheUint64::encrypt(8u64, &client_key),
        ];
        let output = apply_mds_matrix(inputs, &T4_P32_MDS_MATRIX, constants::POSEIDON_P_32 as u64);
        let output: Vec<u64> = output.iter().map(|x| x.decrypt(&client_key)).collect();

        // Print output
        println!("{:?}", output);

        // Expected output based on T4_P32_MDS_MATRIX @ [1, 0, 2, 8]
        // To reproduce:
        // ```
        // from poseidon import Poseidon
        // p32 = 3552575077
        // H32 = Poseidon(p=p32, security_level=32, alpha=5,
        //                input_rate=None, t=4, full_round=8, partial_round=56)
        // H32.mds_matrix @ H32.field_p([1,0,2,8])
        // ```
        let expected: Vec<u64> = vec![3002771793, 913519307, 2467066027, 2864616095];

        // Check
        assert_eq!(output, expected);
    }

    // Test Poseidon end-to-end but with r_full = 2, r_partial = 1
    #[test]
    fn test_poseidon_p32_r1() {
        let (client_key, server_key, _public_key) = utils::init_keys();
        set_server_key(server_key);

        // Inputs
        let inputs: Vec<FheUint32> = vec![
            FheUint32::encrypt(1u32, &client_key),
            FheUint32::encrypt(0u32, &client_key),
            FheUint32::encrypt(2u32, &client_key),
            FheUint32::encrypt(8u32, &client_key),
        ];
        let output = poseidon_p32(inputs.iter().collect(), 2, 1);
        let output: u32 = output.decrypt(&client_key);

        // Expected output based on T4_P32_MDS_MATRIX @ [1, 0, 2, 8]
        // To reproduce:
        // ```
        // from poseidon import Poseidon
        // p32 = 3552575077
        // H32_r1 = Poseidon(p=p32, security_level=32, alpha=5, input_rate=None,
        //                   t=4, full_round=2, partial_round=1)
        // H32_r1.run_hash([1,0,2,8])
        // ```
        let expected: u32 = 1725970220;
        // Check
        assert_eq!(output, expected);
    }

    // Test Poseidon end-to-end
    #[test]
    fn test_poseidon_p32_full() {
        let (client_key, server_key, _public_key) = utils::init_keys();
        set_server_key(server_key);

        // Inputs
        let inputs: Vec<FheUint32> = vec![
            FheUint32::encrypt(1u32, &client_key),
            FheUint32::encrypt(0u32, &client_key),
            FheUint32::encrypt(2u32, &client_key),
            FheUint32::encrypt(8u32, &client_key),
        ];
        let output = poseidon_p32(
            inputs.iter().collect(),
            constants::POSEIDON_R_FULL,
            constants::POSEIDON_R_PARTIAL,
        );
        let output: u32 = output.decrypt(&client_key);

        // Expected output based on T4_P32_MDS_MATRIX @ [1, 0, 2, 8]
        // To reproduce:
        // ```
        // from poseidon import Poseidon
        // p32 = 3552575077
        // H32 = Poseidon(p=p32, security_level=32, alpha=5, input_rate=None,
        //                t=4, full_round=8, partial_round=56)
        // H32.run_hash([1,0,2,8])
        // ```
        let expected: u32 = 1502657535;
        // Check
        assert_eq!(output, expected);
    }
}
