# crypt.py
import os
import base64
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    AES_AVAILABLE = True
except ImportError:
    AES_AVAILABLE = False
from crypt_tools.aes_cipher import encrypt_aes as pure_aes_encrypt, decrypt_aes as pure_aes_decrypt
from crypt_tools.vichaos_chiper import vichaos_encrypt, vichaos_decrypt

# ======================
# === EXCEPTIONS ======
# ======================
class EncryptionError(Exception): pass
class DecryptionError(Exception): pass

# ======================
# === BASE METHODS ====
# ======================
def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def aes_encrypt_bytes(data: bytes, key: str) -> bytes:
    if AES_AVAILABLE:
        key_bytes = key.encode().ljust(32, b'\0')[:32]
        cipher = AES.new(key_bytes, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        return cipher.iv + ct_bytes
    else:
        return pure_aes_encrypt(data, key)

def aes_decrypt_bytes(data: bytes, key: str) -> bytes:
    if AES_AVAILABLE:
        key_bytes = key.encode().ljust(32, b'\0')[:32]
        iv, ct = data[:16], data[16:]
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size)
    else:
        return pure_aes_decrypt(data, key)

def vigenere_encrypt(data: bytes, key: str) -> bytes:
    key_bytes = key.encode()
    return bytes([(b + key_bytes[i % len(key_bytes)]) % 256 for i, b in enumerate(data)])

def vigenere_decrypt(data: bytes, key: str) -> bytes:
    key_bytes = key.encode()
    return bytes([(b - key_bytes[i % len(key_bytes)]) % 256 for i, b in enumerate(data)])

def rc4_crypt(data: bytes, key: str) -> bytes:
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

# =============================
# === GENERIC DATA HANDLER ===
# =============================
def encrypt_data(method: str, data: bytes | str, key: str) -> bytes:
    if isinstance(data, str):
        data = data.encode()
    method = method.lower()

    if method == 'xor':
        return xor_bytes(data, key.encode())
    elif method == 'aes':
        return aes_encrypt_bytes(data, key)
    elif method == 'vigenere':
        return vigenere_encrypt(data, key)
    elif method == 'rc4':
        return rc4_crypt(data, key)
    elif method == 'vichaos':
        return vichaos_encrypt(data, key)
    else:
        raise EncryptionError(f"Unsupported encryption method: {method}")

def decrypt_data(method: str, data: bytes, key: str) -> bytes:
    method = method.lower()

    if method == 'xor':
        return xor_bytes(data, key.encode())
    elif method == 'aes':
        return aes_decrypt_bytes(data, key)
    elif method == 'vigenere':
        return vigenere_decrypt(data, key)
    elif method == 'rc4':
        return rc4_crypt(data, key)
    elif method == 'vichaos':
        return vichaos_decrypt(data, key)
    else:
        raise DecryptionError(f"Unsupported decryption method: {method}")

# ========================
# === FILE BASED MODE ===
# ========================
def encrypt_file(method: str, input_file: str, output_file: str, key: str) -> None:
    try:
        if not os.path.isfile(input_file):
            raise FileNotFoundError(f"Input file not found: {input_file}")
        with open(input_file, 'rb') as f:
            data = f.read()
        encrypted = encrypt_data(method, data, key)
        with open(output_file, 'wb') as f:
            f.write(encrypted)
    except Exception as e:
        raise EncryptionError(f"{method.upper()} encryption failed: {e}")

def decrypt_file(method: str, input_file: str, output_file: str, key: str) -> None:
    try:
        if not os.path.isfile(input_file):
            raise FileNotFoundError(f"Input file not found: {input_file}")
        with open(input_file, 'rb') as f:
            data = f.read()
        decrypted = decrypt_data(method, data, key)
        with open(output_file, 'wb') as f:
            f.write(decrypted)
    except Exception as e:
        raise DecryptionError(f"{method.upper()} decryption failed: {e}")

# ========================
# === STRING HANDLER ==== 
# ========================
def encrypt_string(method: str, text: str, key: str) -> bytes:
    try:
        return encrypt_data(method, text, key)
    except Exception as e:
        raise EncryptionError(f"String encryption failed: {e}")

def decrypt_string(method: str, data: bytes, key: str) -> str:
    try:
        return decrypt_data(method, data, key).decode(errors='ignore')
    except Exception as e:
        raise DecryptionError(f"String decryption failed: {e}")