import hashlib

header = b'XORHead'

def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key or len(key) == 0:
        raise ValueError("Key must not be empty.")

    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    if not key or len(key) == 0:
        raise ValueError("Key must not be empty.")
    checksum = hashlib.sha256(data).digest()[:8]  # 8 bytes checksum
    encrypted = xor_bytes(header + checksum + data, key)
    return encrypted

def xor_decrypt(encrypted: bytes, key: bytes) -> bytes:
    if not key or len(key) == 0:
        raise ValueError("Key must not be empty.")
    decrypted = xor_bytes(encrypted, key)
    if not decrypted.startswith(header):
        raise ValueError("Invalid key or corrupted data.")
    if len(decrypted) < len(header) + 8:
        raise ValueError("Invalid key or corrupted data.")
    checksum = decrypted[len(header):len(header)+8]
    data = decrypted[len(header)+8:]
    if hashlib.sha256(data).digest()[:8] != checksum:
        raise ValueError("Invalid key or corrupted data.")
    return data