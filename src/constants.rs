pub const SCH_P_128: u128 = 248887481077937771352227813962501876493;
pub const SCH_G_128: u128 = 119623129323905044429391025715657774932;
pub const SCH_Q_64: u64 = 12223110294319142443;

pub const SCH_P_32: u32 = 3552575077;
pub const SCH_G_32: u32 = 3196401078;
pub const SCH_Q_16: u16 = 43607;

pub const POSEIDON_P_128: u128 = SCH_P_128;    // NOTE: use the same prime
pub const POSEIDON_P_32: u32 = SCH_P_32;       // NOTE: use the same prime
pub const POSEIDON_ALPHA: u8 = 5;              // Alpha constant
pub const POSEIDON_T: usize = 4;               // Number of state elements
pub const POSEIDON_R_FULL: usize = 8;          // Number of full rounds
pub const POSEIDON_R_PARTIAL: usize = 56;      // Number of partial rounds



/////////////// Tests below ///////////////

#[cfg(test)]
mod tests {
    use super::*;
    use miller_rabin::is_prime;
    use num::{FromPrimitive, PrimInt};
    use num_bigint::BigUint;

    // Check prime up to u128
    fn check_prime<T>(num: T) -> bool
    where
        T: PrimInt + FromPrimitive,
    {
        let n_u128: u128 = T::to_u128(&num).unwrap();
        is_prime(&BigUint::from(n_u128), 10)
    }

    #[test]
    fn test_constants() {
        // Prime check
        assert!(check_prime(SCH_Q_16), "SCH_Q_16 is not a prime");
        assert!(check_prime(SCH_Q_64), "SCH_Q_64 is not a prime");
        assert!(check_prime(SCH_P_32), "SCH_P_32 is not a prime");
        assert!(check_prime(SCH_P_128), "SCH_P_128 is not a prime");

        // Check if g^q mod p == 1
        let one = BigUint::from(1_u32);
        let result =
            BigUint::from(SCH_G_128).modpow(&BigUint::from(SCH_Q_64), &BigUint::from(SCH_P_128));
        assert_eq!(result, one, "g^q mod p is not equal to 1 (128-bit p)");
        let result =
            BigUint::from(SCH_G_32).modpow(&BigUint::from(SCH_Q_16), &BigUint::from(SCH_P_32));
        assert_eq!(result, one, "g^q mod p is not equal to 1 (32-bit p)");

        // Check if p - 1 is a multiple of q
        let result = (BigUint::from(SCH_P_128) - &one) % BigUint::from(SCH_Q_64);
        assert_eq!(
            result,
            BigUint::from(0_u32),
            "SCH_P_128 - 1 is not a multiple of SCH_Q_64"
        );
        let result = (BigUint::from(SCH_P_32) - &one) % BigUint::from(SCH_Q_16);
        assert_eq!(
            result,
            BigUint::from(0_u32),
            "SCH_P_32 - 1 is not a multiple of SCH_Q_16"
        );
    }
}
