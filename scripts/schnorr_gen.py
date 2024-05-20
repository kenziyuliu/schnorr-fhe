from Crypto.Util import number
import Crypto.Random
from loguru import logger
import typer


def generate_p_q(len_p, len_q):
    assert len_p > len_q, "Bit length of p must be greater than bit length of q"

    # Step 1: Pick the prime q
    logger.info(f"Generating a prime q of bit length {len_q}")
    q = number.getPrime(len_q)

    # Step 2: Pick a large value X (about the same size as the desired p)
    X = number.getRandomNBitInteger(len_p)

    # Step 3: Compute p = X - (X mod 2q) + 1 (i.e., now p = 1 (mod 2q))
    # Check whether p is prime, repeat steps if p is not prime
    logger.info(f"Generating a prime p of bit length {len_p}")
    p = X - (X % (2 * q)) + 1
    while not number.isPrime(p):
        X = number.getRandomNBitInteger(len_p)
        p = X - (X % (2 * q)) + 1

    return p, q


def generate_g(p, q):
    h = 2
    while True:
        g = pow(h, (p - 1) // q, p)
        if g > 1:
            return g
        h += 1


def generate_schnorr_params(len_p, len_q):
    p, q = generate_p_q(len_p, len_q)
    g = generate_g(p, q)
    return p, q, g


# Verification
def verify_params(p, q, g):
    print(f'{p.bit_length()=}, {number.isPrime(p)=}')
    print(f'{q.bit_length()=}, {number.isPrime(q)=}')
    print(f'{g.bit_length()=}')
    assert number.isPrime(p), "p is not prime"
    assert number.isPrime(q), "q is not prime"
    assert pow(g, q, p) == 1, "g^q mod p is not 1"
    assert (p - 1) % q == 0, "p is not 1 mod q"


def main(len_p: int = 128, len_q: int = 64):
    p, q, g = generate_schnorr_params(len_p, len_q)

    logger.info(f"Generated parameters:")
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"g = {g}")

    verify_params(p, q, g)
    logger.info("Parameters are correctly generated and verified.")


if __name__ == "__main__":
    typer.run(main)
