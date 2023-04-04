import random
from math import gcd

def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, n):
        if n % i == 0:
            return False
    return True

def generate_prime(lower, upper):
    prime_candidates = [i for i in range(lower, upper) if is_prime(i)]
    return random.choice(prime_candidates)

def lcm(a, b):
    return abs(a * b) // gcd(a, b)

def mod_inverse(a, m):
    for x in range(1, m):
        if ((a * x) % m == 1):
            return x
    return -1

def generate_key_pair():
    p = generate_prime(100, 300)
    q = generate_prime(100, 300)

    n = p * q
    phi = lcm(p - 1, q - 1)

    e = random.randrange(2, phi)

    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(2, phi)
        g = gcd(e, phi)

    d = mod_inverse(e, phi)

    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

def encrypt(plain_text, public_key):
    e, n = public_key
    if isinstance(plain_text, str):
        plain_text = plain_text.encode('utf-8')
    return [pow(b, e, n) for b in plain_text]


def decrypt(cipher_text, private_key):
    d, n = private_key
    decrypted_bytes = bytes([pow(char, d, n) for char in cipher_text])
    return decrypted_bytes


if __name__ == '__main__':
    public_key, private_key = generate_key_pair()
    print(f"Public key: {public_key}")
    print(f"Private key: {private_key}")

    plain_text = "Hello, RSA!"
    print(f"Plain text: {plain_text}")

    cipher_text = encrypt(plain_text, public_key)
    print(f"Cipher text: {cipher_text}")

    decrypted_text = decrypt(cipher_text, private_key)
    print(f"Decrypted text: {decrypted_text}")
