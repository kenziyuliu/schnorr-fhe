from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.backends import default_backend
from Crypto.Util import number
import typer


def generate_schnorr_parameters(p_bit_length):
    # Generate DSA parameters, which can be adapted for Schnorr
    dsa_parameters = dsa.generate_parameters(key_size=p_bit_length, backend=default_backend())

    # Extract p, q and g
    p = dsa_parameters.parameter_numbers().p
    q = dsa_parameters.parameter_numbers().q
    g = dsa_parameters.parameter_numbers().g

    # Ensure the bit lengths are as specified
    # assert p.bit_length() == p_bit_length, f'{p.bit_length()=}'
    # assert q.bit_length() == q_bit_length, f'{q.bit_length()=}'

    return g, p, q


# Verification
def verify_params(p, q, g):
    print(f'{p.bit_length()=}, {number.isPrime(p)=}')
    print(f'{q.bit_length()=}, {number.isPrime(q)=}')
    print(f'{g.bit_length()=}')
    assert number.isPrime(p), "p is not prime"
    assert number.isPrime(q), "q is not prime"
    assert pow(g, q, p) == 1, "g^q mod p is not 1"
    assert (p - 1) % q == 0, "p is not 1 mod q"


def main(len_p: int):
    # Generate Schnorr parameters with specified bit lengths
    g, p, q = generate_schnorr_parameters(len_p)

    # Print the generated parameters
    print("g =", g)
    print("p =", p)
    print("q =", q)
    verify_params(p, q, g)


if __name__ == "__main__":
    typer.run(main)
