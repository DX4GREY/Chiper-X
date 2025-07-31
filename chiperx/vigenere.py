VIGENERE_MAGIC = b"Vigenere"

class DecryptionError(Exception):
    pass

def vigenere_encrypt(data: bytes, key: str) -> bytes:
    key_bytes = key.encode()
    data = VIGENERE_MAGIC + data
    return bytes([(b + key_bytes[i % len(key_bytes)]) % 256 for i, b in enumerate(data)])

def vigenere_decrypt(data: bytes, key: str) -> bytes:
    key_bytes = key.encode()
    decrypted = bytes([(b - key_bytes[i % len(key_bytes)]) % 256 for i, b in enumerate(data)])
    if not decrypted.startswith(VIGENERE_MAGIC):
        raise DecryptionError("Vigenère: Invalid key or corrupted data")
    return decrypted[len(VIGENERE_MAGIC):]