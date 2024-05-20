pub const SCH_P: u128 = 248887481077937771352227813962501876493;
pub const SCH_G: u128 = 119623129323905044429391025715657774932;
pub const SCH_Q: u64 = 12223110294319142443;


#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use miller_rabin::is_prime;

    fn is_prime_u128(num: u128) -> bool {
        let big_num = BigUint::from(num);
        is_prime(&big_num, 5) // 5 rounds for good accuracy
    }

    fn is_prime_u64(num: u64) -> bool {
        is_prime(&BigUint::from(num), 5) // 5 rounds for good accuracy
    }

    #[test]
    fn test_constants() {
        // Check if SCH_P is prime
        assert!(is_prime_u128(SCH_P), "SCH_P is not a prime");

        // Check if SCH_Q is prime
        assert!(is_prime_u64(SCH_Q), "SCH_Q is not a prime");

        // Check if g^q mod p == 1
        let p = BigUint::from(SCH_P);
        let g = BigUint::from(SCH_G);
        let q = BigUint::from(SCH_Q);
        let one = BigUint::from(1_u32);

        let result = g.modpow(&q, &p);
        assert_eq!(result, one, "g^q mod p is not equal to 1");

        // Check if SCH_P - 1 is a multiple of SCH_Q
        let p_minus_1 = p - 1_u32;
        let result = p_minus_1 % q;
        assert_eq!(result, BigUint::from(0_u32), "SCH_P - 1 is not a multiple of SCH_Q");
    }
}