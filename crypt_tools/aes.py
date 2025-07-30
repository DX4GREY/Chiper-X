import os
from typing import Union

# AES S-box and inverse S-box
Sbox = [
    99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,
    202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,
    183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,
    4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,
    9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,
    83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,
    208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,
    81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,
    205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,
    96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,
    224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,
    231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,
    186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,
    112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,
    225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,
    140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22
]

InvSbox = [0]*256
for i in range(256):
    InvSbox[Sbox[i]] = i

# Round constants
Rcon = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length"""
    return bytes(x ^ y for x, y in zip(a, b))

def pad(data: bytes, block_size: int = 16) -> bytes:
    """PKCS#7 padding"""
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)

def unpad(data: bytes) -> bytes:
    """PKCS#7 unpadding"""
    if not data:
        return data
    pad_len = data[-1]
    if pad_len > len(data):
        raise ValueError("Invalid padding")
    # Verify all padding bytes are correct
    if not all(byte == pad_len for byte in data[-pad_len:]):
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]

def pad_key(key: Union[str, bytes], target_length: int = 16) -> bytes:
    """Pad or truncate key to target length (16, 24, or 32 bytes)"""
    if isinstance(key, str):
        key = key.encode('utf-8')
    if len(key) >= target_length:
        return key[:target_length]
    return key + bytes([0] * (target_length - len(key)))

def gmul(a: int, b: int) -> int:
    """Galois Field multiplication"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit = a & 0x80
        a <<= 1
        if hi_bit:
            a ^= 0x1B
        b >>= 1
    return p & 0xFF

def sub_word(word: bytes) -> bytes:
    """Substitute each byte using S-box"""
    return bytes(Sbox[b] for b in word)

def rot_word(word: bytes) -> bytes:
    """Rotate word left by 1 byte"""
    return word[1:] + word[:1]

def expand_key(key: Union[str, bytes]) -> list:
    """Key expansion for AES-128"""
    key_bytes = pad_key(key, 16)  # AES-128 uses 16-byte keys
    key_schedule = [list(key_bytes[i:i+4]) for i in range(0, 16, 4)]
    
    for i in range(4, 44):  # 10 rounds for AES-128
        temp = key_schedule[i-1]
        if i % 4 == 0:
            temp = list(x ^ y for x, y in zip(sub_word(rot_word(bytes(temp))), 
                       [Rcon[i//4 - 1], 0, 0, 0]))
        key_schedule.append([x ^ y for x, y in zip(key_schedule[i-4], temp)])
    
    return key_schedule

def sub_bytes(state: bytes) -> bytes:
    """Byte substitution using S-box"""
    return bytes(Sbox[b] for b in state)

def shift_rows(state: bytes) -> bytes:
    """Shift rows transformation"""
    return bytes([
        state[0], state[5], state[10], state[15],
        state[4], state[9], state[14], state[3],
        state[8], state[13], state[2], state[7],
        state[12], state[1], state[6], state[11]
    ])

def mix_columns(state: bytes) -> bytes:
    """Mix columns transformation"""
    new_state = []
    for i in range(0, 16, 4):
        a, b, c, d = state[i:i+4]
        new_state.extend([
            gmul(a, 2) ^ gmul(b, 3) ^ c ^ d,
            a ^ gmul(b, 2) ^ gmul(c, 3) ^ d,
            a ^ b ^ gmul(c, 2) ^ gmul(d, 3),
            gmul(a, 3) ^ b ^ c ^ gmul(d, 2)
        ])
    return bytes(new_state)

def aes_encrypt_block(block: bytes, key_schedule: list) -> bytes:
    """Encrypt a single 16-byte block"""
    state = xor_bytes(block, bytes(sum(key_schedule[:4], [])))
    for round in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = xor_bytes(state, bytes(sum(key_schedule[round*4:round*4+4], [])))
    state = sub_bytes(state)
    state = shift_rows(state)
    state = xor_bytes(state, bytes(sum(key_schedule[40:44], [])))  # Last round
    return state

def inv_sub_bytes(state: bytes) -> bytes:
    """Inverse byte substitution"""
    return bytes(InvSbox[b] for b in state)

def inv_shift_rows(state: bytes) -> bytes:
    """Inverse shift rows"""
    return bytes([
        state[0], state[13], state[10], state[7],
        state[4], state[1], state[14], state[11],
        state[8], state[5], state[2], state[15],
        state[12], state[9], state[6], state[3]
    ])

def inv_mix_columns(state: bytes) -> bytes:
    """Inverse mix columns"""
    new_state = []
    for i in range(0, 16, 4):
        a, b, c, d = state[i:i+4]
        new_state.extend([
            gmul(a, 14) ^ gmul(b, 11) ^ gmul(c, 13) ^ gmul(d, 9),
            gmul(a, 9) ^ gmul(b, 14) ^ gmul(c, 11) ^ gmul(d, 13),
            gmul(a, 13) ^ gmul(b, 9) ^ gmul(c, 14) ^ gmul(d, 11),
            gmul(a, 11) ^ gmul(b, 13) ^ gmul(c, 9) ^ gmul(d, 14)
        ])
    return bytes(new_state)

def aes_decrypt_block(block: bytes, key_schedule: list) -> bytes:
    """Decrypt a single 16-byte block"""
    state = xor_bytes(block, bytes(sum(key_schedule[40:44], [])))  # Last round first
    for round in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = xor_bytes(state, bytes(sum(key_schedule[round*4:round*4+4], [])))
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = xor_bytes(state, bytes(sum(key_schedule[:4], [])))  # Initial round
    return state

def aes_encrypt_cbc(data: Union[str, bytes], key: Union[str, bytes]) -> bytes:
    """AES-CBC encryption"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    iv = os.urandom(16)
    key_schedule = expand_key(key)
    padded_data = pad(data)
    encrypted = iv  # Prepend IV
    
    previous_block = iv
    for i in range(0, len(padded_data), 16):
        block = padded_data[i:i+16]
        xored = xor_bytes(block, previous_block)
        encrypted_block = aes_encrypt_block(xored, key_schedule)
        encrypted += encrypted_block
        previous_block = encrypted_block
    
    return encrypted

def aes_decrypt_cbc(data: bytes, key: Union[str, bytes]) -> bytes:
    """AES-CBC decryption"""
    if len(data) < 32 or len(data) % 16 != 0:
        raise ValueError("Invalid ciphertext length")
    
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    iv = data[:16]
    ciphertext = data[16:]
    key_schedule = expand_key(key)
    decrypted = b""
    
    previous_block = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted_block = aes_decrypt_block(block, key_schedule)
        plaintext_block = xor_bytes(decrypted_block, previous_block)
        decrypted += plaintext_block
        previous_block = block
    
    return unpad(decrypted)