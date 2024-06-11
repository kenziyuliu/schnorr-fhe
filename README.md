# Schnorr-FHE

(**Work in progress**)

This is a Rust implementation of the Schnorr signature scheme under fully homomorphic encryption (FHE) for the signing process. The intuition is that the signing process can be done entirely in the FHE space by a public entity (say a coordinator / server) to produce an *encrypted* signature; only the true signer (who holds the FHE decryption key) can decrypt the signature to obtain the actual signature to be verified. The motivation is that we can reduce the number of communication round trips between the coordinator and the signer(s) for a threshold signature to one. See https://eprint.iacr.org/2017/956.pdf for more details.

This "Schnorr-FHE" signature scheme works roughly as follows:

1. The signer releases encrypted secret signing key `E(x_sch)`
2. The coordinator receives the message `m` to be signed
3. The coordinator signs the message `m` entirely in the FHE space
4. The coordinator sends the encypted signature `E(s), E(h)` to the signer for decryption
5. The signer decrypts the signature to obtain the actual signature `(s, h)` to be verified by the coordinator.

Threshold signatures are not yet implemented.

The FHE scheme used is TFHE, a ring-LWE-based FHE scheme. We use the Rust implementation [ `TFHE-rs` ](https://github.com/zama-ai/tfhe-rs).

The hash function used is [Poseidon](https://eprint.iacr.org/2019/458.pdf), with references to the [Python implementation](https://github.com/ingonyama-zk/poseidon-hash/).

## Implementation TODOs

* [ ] Elliptic curve implementation
    - [ ] Implement EC arithmetic operations
    - [ ] Implement small primes (<= 16-bit) for dev purposes
    - [ ] Implement curve25519 (256-bit prime)

* [ ] Optimization
    - [ ] Montgomery multiplication to avoid 2x bitwidth for multiplication?
    - [ ] Implement clear^FHE
    - [ ] Optimize FHE modexp that currently uses FHE bit-decomposition for every bit

* [ ] Refactoring (drastically improve code sharing; Ken's not great with Rust yet)
    - [ ] Implement abstraction over different bit sizes

* [x] Schnorr-FHE Setup
    - [x] x_sch and y_sch generation
    - [x] FHE encryption of x_sch

* [x] Schnorr-FHE Signing
    - [x] Implement FHE hashing of FHE(secret key) & FHE(message) as the signing "randomness" k
        - i.e. FHE(k) = H(FHE(m), FHE(x_sch)) % q
        - Note that we *cannot* get around FHE hashing -- since we must
          hash the encrypted key

        - This is the 1st FHE hash
        - Note that hash output should be mod q
    - [x] Compute FHE(r) = FHE(g)^FHE(k) (mod p)
    - [x] Compute FHE(h) = H(FHE(m), FHE(r)) (mod q)
    - [x] Compute FHE(s) = (FHE(k) - FHE(h) * FHE(x_sch)) (mod q)
    - [x] Client decryption of FHE(s) and FHE(h) to get s and h

* [x] Schnorr-FHE Verification
    - [x] Compute r_v = g^s * y_sch^h (mod p)
        - g, y_sch is public; s, h is from client
        - This is done in the clear
        - Valid signature gives r_v = g^(k - h * x_sch) * (g)^(h * x_sch) = g^k, where k = H(x_sch, M)
    - [x] Compute h_v = H(M, r_v) in the clear
    - [x] Verify h == h_v

* [x] Implement FHE Poseidon
    - [x] Implement 32-bit version in FheUint64: `poseidon::poseidon_p32_impl`
    - Implement 16-bit version in FheUint32: `poseidon::poseidon_p16_impl`
        - Generate round constants / MDS matrix for 16-bit version
    - Implement 64-bit version in FheUint128: `poseidon::poseidon_p128_impl`
        - Generate round constants / MDS matrix for 64-bit version
    - [x] Implement 32-bit version in the clear

* [x] Schnorr key selection: generate p, q, g for different bits (Python is fine)

* [x] Hardcode round constants of Poseidon
    - [x] No need to encrypt in FHE space, since binary ops on FheUints and clears are supported

* Scaling behavior: implementation/refactoring to support different number of bits
    - (r) Plain Rust doesn't have u256 so we'll use `tfhe::integer::bigint::u256::U256`

* Behavioral tests
    - [x] adding/multiplying plaintexts to FheUints
    - [x] Checking prime modular operations with clear
    - [x] Test 256-bit integer operations (very slow on laptop)

* Unit tests
    - Poseidon hash: FHE and clear versions
    - FHE exponentiation
