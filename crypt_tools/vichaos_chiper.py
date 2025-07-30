def expand_key(key: bytes, length: int) -> list[int]:
    """Expand key ke panjang data dengan formula dinamis."""
    return [(key[i % len(key)] + i**2 + 3*i) % 256 for i in range(length)]

def permute(x: int, i: int, ki: int) -> int:
    """Permutasi pseudo-chaotic untuk tiap byte."""
    return (x + (i * ki)) % 256

def inverse_permute(c: int, i: int, ki: int) -> int:
    """Inverse dari permutasi pseudo-chaotic."""
    return (c - (i * ki)) % 256

def vichaos_encrypt(data: bytes, key: str) -> bytes:
    """Enkripsi data dengan algoritma Vichaos."""
    key_bytes = key.encode()
    k_star = expand_key(key_bytes, len(data))
    encrypted = []
    for i, b in enumerate(data):
        v = (b + k_star[i]) % 256
        x = v ^ k_star[(i + 1) % len(data)]
        c = permute(x, i, k_star[i])
        encrypted.append(c)
    return bytes(encrypted)

def vichaos_decrypt(data: bytes, key: str) -> bytes:
    """Dekripsi data dengan algoritma Vichaos."""
    key_bytes = key.encode()
    k_star = expand_key(key_bytes, len(data))
    decrypted = []
    for i, c in enumerate(data):
        x = inverse_permute(c, i, k_star[i])
        v = x ^ k_star[(i + 1) % len(data)]
        p = (v - k_star[i]) % 256
        decrypted.append(p)
    return bytes(decrypted)