import os
import hmac
import hashlib

MAGIC_HEADER = b"ViChaos-Dx4"
SALT_SIZE = 16
HMAC_SIZE = 32
KDF_ITER = 100_000

def expand_key(key: bytes, length: int) -> list[int]:
    return [(key[i % len(key)] + i**2 + 3*i) % 256 for i in range(length)]

def permute(x: int, i: int, ki: int) -> int:
    return (x + (i * ki)) % 256

def inverse_permute(c: int, i: int, ki: int) -> int:
    return (c - (i * ki)) % 256

def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, KDF_ITER, dklen=32)

def vichaos_secure_encrypt(data: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    
    full_data = MAGIC_HEADER + data
    k_star = expand_key(key, len(full_data))
    
    encrypted = []
    for i, b in enumerate(full_data):
        v = (b + k_star[i]) % 256
        x = v ^ k_star[(i + 1) % len(full_data)]
        c = permute(x, i, k_star[i])
        encrypted.append(c)
    
    cipher_bytes = bytes(encrypted)
    
    # Tambahkan HMAC sebagai integrity check
    hmac_digest = hmac.new(key, cipher_bytes, hashlib.sha256).digest()
    
    return MAGIC_HEADER + salt + hmac_digest + cipher_bytes

def vichaos_secure_decrypt(data: bytes, password: str) -> bytes:
    if not data.startswith(MAGIC_HEADER):
        raise ValueError("Invalid header")

    offset = len(MAGIC_HEADER)
    salt = data[offset:offset+SALT_SIZE]
    hmac_expected = data[offset+SALT_SIZE : offset+SALT_SIZE+HMAC_SIZE]
    cipher_bytes = data[offset+SALT_SIZE+HMAC_SIZE:]
    
    key = derive_key(password, salt)
    
    # Verifikasi HMAC
    hmac_actual = hmac.new(key, cipher_bytes, hashlib.sha256).digest()
    if not hmac.compare_digest(hmac_actual, hmac_expected):
        raise ValueError("HMAC verification failed: wrong password or data tampered")

    k_star = expand_key(key, len(cipher_bytes))
    
    decrypted = []
    for i, c in enumerate(cipher_bytes):
        x = inverse_permute(c, i, k_star[i])
        v = x ^ k_star[(i + 1) % len(cipher_bytes)]
        p = (v - k_star[i]) % 256
        decrypted.append(p)

    decrypted_data = bytes(decrypted)
    
    if not decrypted_data.startswith(MAGIC_HEADER):
        raise ValueError("Magic header mismatch")

    return decrypted_data[len(MAGIC_HEADER):]