# Schnorr-FHE

## Implementation TODOs

* Schnorr-FHE Setup
    - (d) x_sch and y_sch generation
    - (d) FHE encryption of x_sch

* (d) Schnorr-FHE Signing
    - (d) Implement FHE hashing of FHE(secret key) & FHE(message) as the signing "randomness" k
        - i.e. FHE(k) = H(FHE(m), FHE(x_sch)) % q
        - Note that we *cannot* get around FHE hashing -- since we must
          hash the encrypted key
        - This is the 1st FHE hash
        - Note that hash output should be mod q
    - (d) Compute FHE(r) = FHE(g)^FHE(k) (mod p)
    - (d) Compute FHE(h) = H(FHE(m), FHE(r)) (mod q)
    - (d) Compute FHE(s) = (FHE(k) - FHE(h) * FHE(x_sch)) (mod q)
    - (d) Client decryption of FHE(s) and FHE(h) to get s and h

* (d) Schnorr-FHE Verification
    - (d) Compute r_v = g^s * y_sch^h (mod p)
        - g, y_sch is public; s, h is from client
        - This is done in the clear
        - Valid signature gives r_v = g^(k - h * x_sch) * (g)^(h * x_sch) = g^k, where k = H(x_sch, M)
    - (d) Compute h_v = H(M, r_v) in the clear
    - (d) Verify h == h_v


* (d) Implement FHE Poseidon
    - (d) Implement 32-bit version in FheUint64: `poseidon::poseidon_p32_impl`
    - Implement 16-bit version in FheUint32: `poseidon::poseidon_p16_impl`
    - Implement 64-bit version in FheUint128: `poseidon::poseidon_p128_impl`
    - (d) Implement 32-bit version in the clear

* (d) Schnorr key selection: generate p, q, g for different bits (Python is fine)

* (d) Hardcode round constants of Poseidon
    - (d) No need to encrypt in FHE space, since binary ops on FheUints and clears are supported

* Scaling behavior: implementation/refactoring to support different number of bits
    - (r) Plain Rust doesn't have u256 so we'll use `tfhe::integer::bigint::u256::U256`

* Behavioral tests
    - (d) adding/multiplying plaintexts to FheUints
    - (d) Checking prime modular operations with clear
    - (d) Test 256-bit integer operations (very slow on laptop)

* Unit tests
    - Poseidon hash: FHE and clear versions
    - FHE exponentiation
