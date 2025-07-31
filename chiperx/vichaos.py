MAGIC_HEADER = b"ViChaos-Dx4"  # Penanda untuk validasi key saat decrypt

def expand_key(key: bytes, length: int) -> list[int]:
    return [(key[i % len(key)] + i**2 + 3*i) % 256 for i in range(length)]

def permute(x: int, i: int, ki: int) -> int:
    return (x + (i * ki)) % 256

def inverse_permute(c: int, i: int, ki: int) -> int:
    return (c - (i * ki)) % 256

def vichaos_encrypt(data: bytes, key: str) -> bytes:
    key_bytes = key.encode()
    full_data = MAGIC_HEADER + data  # tambahkan header
    k_star = expand_key(key_bytes, len(full_data))
    encrypted = []
    for i, b in enumerate(full_data):
        v = (b + k_star[i]) % 256
        x = v ^ k_star[(i + 1) % len(full_data)]
        c = permute(x, i, k_star[i])
        encrypted.append(c)
    return bytes(encrypted)

def vichaos_decrypt(data: bytes, key: str) -> bytes:
    key_bytes = key.encode()
    k_star = expand_key(key_bytes, len(data))
    decrypted = []
    for i, c in enumerate(data):
        x = inverse_permute(c, i, k_star[i])
        v = x ^ k_star[(i + 1) % len(data)]
        p = (v - k_star[i]) % 256
        decrypted.append(p)
    decrypted_data = bytes(decrypted)
    
    # 🔒 Validasi magic header
    if not decrypted_data.startswith(MAGIC_HEADER):
        raise ValueError("Invalid key or corrupted data (magic header mismatch)")
    
    return decrypted_data[len(MAGIC_HEADER):]  # buang header sebelum return