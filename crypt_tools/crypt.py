import os

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    AES_AVAILABLE = True
except ImportError:
    AES_AVAILABLE = False

class EncryptionError(Exception): pass
class DecryptionError(Exception): pass

def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def aes_encrypt_bytes(data: bytes, key: str) -> bytes:
    if not AES_AVAILABLE:
        raise ImportError("pycryptodome not installed, AES not available")
    key_bytes = key.encode().ljust(32, b'\0')[:32]
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct_bytes

def aes_decrypt_bytes(data: bytes, key: str) -> bytes:
    if not AES_AVAILABLE:
        raise ImportError("pycryptodome not installed, AES not available")
    key_bytes = key.encode().ljust(32, b'\0')[:32]
    iv, ct = data[:16], data[16:]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

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

# =============================
# === GENERIC DATA HANDLER ===
# =============================
def encrypt_data(method: str, data: bytes | str, key: str) -> bytes:
    if isinstance(data, str):
        data = data.encode()
    if method.lower() == 'xor':
        return xor_bytes(data, key.encode())
    elif method.lower() == 'aes':
        return aes_encrypt_bytes(data, key)
    else:
        raise EncryptionError(f"Unsupported encryption method: {method}")

def decrypt_data(method: str, data: bytes, key: str) -> bytes:
    if method.lower() == 'xor':
        return xor_bytes(data, key.encode())
    elif method.lower() == 'aes':
        return aes_decrypt_bytes(data, key)
    else:
        raise DecryptionError(f"Unsupported decryption method: {method}")

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