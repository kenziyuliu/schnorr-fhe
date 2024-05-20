from sympy import isprime, randprime
from random import getrandbits

def generate_prime(bit_length):
    while True:
        p_candidate = getrandbits(bit_length)
        if isprime(p_candidate):
            return p_candidate

# Example: Generate a 256-bit prime
prime_p = generate_prime(256)
# Ensure q divides p-1 and q is of appropriate bit length
prime_q = randprime(2**(bit_length//2 - 1), 2**(bit_length//2))

print("Prime p:", prime_p)
print("Prime q:", prime_q)