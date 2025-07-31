RC4_MAGIC = b"RC4"

class DecryptionError(Exception):
    pass

def rc4_encrypt(data: bytes, key: str) -> bytes:
    return RC4_MAGIC + _rc4_core(data, key)

def rc4_decrypt(data: bytes, key: str) -> bytes:
    decrypted = _rc4_core(data, key)
    if not decrypted.startswith(RC4_MAGIC):
        raise DecryptionError("RC4: Invalid key or corrupted data")
    return decrypted[len(RC4_MAGIC):]

def _rc4_core(data: bytes, key: str) -> bytes:
    S = list(range(256))
    j = 0
    out = []

    key_bytes = key.encode()
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])

    return bytes(out)