import os
from .xor import xor_bytes
from .aes import aes_encrypt_cbc, aes_decrypt_cbc
from .vigenere import vigenere_encrypt, vigenere_decrypt
from .rc4 import rc4_encrypt, rc4_decrypt, DecryptionError as RC4DecryptionError
from .vichaos import vichaos_encrypt, vichaos_decrypt

class EncryptionError(Exception):
    pass

class DecryptionError(Exception):
    pass

def encrypt_data(method: str, data: bytes, key: str) -> bytes:
    try:
        if method == 'xor':
            return xor_bytes(data, key.encode())
        elif method == 'aes':
            return aes_encrypt_cbc(data, key)
        elif method == 'vigenere':
            return vigenere_encrypt(data, key)
        elif method == 'rc4':
            return rc4_encrypt(data, key)
        elif method == 'vichaos':
            return vichaos_encrypt(data, key)
        else:
            raise EncryptionError(f"Unknown method: {method}")
    except Exception as e:
        raise EncryptionError(str(e))

def decrypt_data(method: str, data: bytes, key: str) -> bytes:
    try:
        if method == 'xor':
            return xor_bytes(data, key.encode())
        elif method == 'aes':
            return aes_decrypt_cbc(data, key)
        elif method == 'vigenere':
            return vigenere_decrypt(data, key)
        elif method == 'rc4':
            return rc4_decrypt(data, key)
        elif method == 'vichaos':
            return vichaos_decrypt(data, key)
        else:
            raise DecryptionError(f"Unknown method: {method}")
    except (ValueError, RC4DecryptionError) as e:
        raise DecryptionError(str(e))
    except Exception as e:
        raise DecryptionError("Decryption failed: " + str(e))

def encrypt_file(method: str, input_file: str, output_file: str, key: str):
    if not os.path.isfile(input_file):
        raise FileNotFoundError(f"File not found: {input_file}")

    with open(input_file, "rb") as f:
        data = f.read()

    encrypted = encrypt_data(method, data, key)

    with open(output_file, "wb") as f:
        f.write(encrypted)

def decrypt_file(method: str, input_file: str, output_file: str, key: str):
    if not os.path.isfile(input_file):
        raise FileNotFoundError(f"File not found: {input_file}")

    with open(input_file, "rb") as f:
        data = f.read()

    decrypted = decrypt_data(method, data, key)

    with open(output_file, "wb") as f:
        f.write(decrypted)