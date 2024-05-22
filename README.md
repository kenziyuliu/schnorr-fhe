# Schnorr-FHE



## Implementation TODOs

- Hardcode round constants of Poseidon
    - No need to encrypt in FHE space

- Implement Schnorr steps
    - (d) x_sch and y_sch generation
    - (d) FHE encryption of x_sch


- Implement Poseidon

- Implement FHE hashing of FHE(secret key) & FHE(message) as the signing "randomness"
    - Here, we should have r = H(FHE(sk), FHE(m))
    - Note that you *cannot* get around FHE hashing -- since we must hash the
      encrypted key

- (lo) Implement toggle to larger number of bits
    - (r) Plain Rust doesn't have u256, so we will just operate from tfhe::integer::bigint::u256::U256



- Tests
    - (d) adding/multiplying plaintexts to FheUints
    - (d) Checking prime modular operations with clear
    - (d) Test 256-bit integer operations (very slow on laptop)
