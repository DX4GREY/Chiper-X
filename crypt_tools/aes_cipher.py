# aes_cipher.py (Pure Python AES CBC)

from typing import List
import hashlib
# AES pure Python implementation (CBC mode)

def pad(data: bytes, block_size: int = 16) -> bytes:
    padding_len = block_size - len(data) % block_size
    return data + bytes([padding_len] * padding_len)


def unpad(data: bytes) -> bytes:
    padding_len = data[-1]
    if padding_len > len(data):
        raise ValueError("Invalid padding")
    return data[:-padding_len]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# S-box and inverse S-box
Sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]


# Rijndael Rcon
Rcon = [
    0x00, 0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
]

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(i ^ j for i, j in zip(a, b))

def sub_bytes(state: List[int]) -> List[int]:
    return [Sbox[b] for b in state]

def shift_rows(s: List[int]) -> List[int]:
    return [
        s[0], s[5], s[10], s[15],
        s[4], s[9], s[14], s[3],
        s[8], s[13], s[2], s[7],
        s[12], s[1], s[6], s[11]
    ]

def mix_columns(s: List[int]) -> List[int]:
    def xtime(a): return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1
    res = []
    for i in range(4):
        a = s[i*4:(i+1)*4]
        res.extend([
            xtime(a[0]) ^ xtime(a[1]) ^ a[1] ^ a[2] ^ a[3],
            a[0] ^ xtime(a[1]) ^ xtime(a[2]) ^ a[2] ^ a[3],
            a[0] ^ a[1] ^ xtime(a[2]) ^ xtime(a[3]) ^ a[3],
            xtime(a[0]) ^ a[0] ^ a[1] ^ a[2] ^ xtime(a[3])
        ])
    return res

def add_round_key(s: List[int], k: List[int]) -> List[int]:
    return [a ^ b for a, b in zip(s, k)]

def key_expansion(key: bytes) -> List[List[int]]:
    key_symbols = list(key)
    assert len(key_symbols) == 16
    key_schedule = [key_symbols[i:i+4] for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = key_schedule[i - 1]
        if i % 4 == 0:
            temp = [Sbox[b] for b in temp[1:] + temp[:1]]
            temp[0] ^= Rcon[i // 4]
        key_schedule.append([a ^ b for a, b in zip(key_schedule[i - 4], temp)])
    return [sum(key_schedule[i:i+4], []) for i in range(0, 44, 4)]

def aes_encrypt_block(block: bytes, key: bytes) -> bytes:
    assert len(block) == 16
    round_keys = key_expansion(key)
    state = list(block)
    state = add_round_key(state, round_keys[0])
    for i in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[i])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    return bytes(state)

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if not 0 < pad_len <= 16:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def encrypt_aes(data: bytes, key: str) -> bytes:
    key_bytes = key.encode("utf-8")[:16].ljust(16, b"\0")
    iv = bytes([0]*16)
    data = pkcs7_pad(data)
    out = b""
    prev = iv
    for i in range(0, len(data), 16):
        block = xor_bytes(data[i:i+16], prev)
        enc = aes_encrypt_block(block, key_bytes)
        out += enc
        prev = enc
    return out

def decrypt_aes(data: bytes, key: str) -> bytes:
    key_bytes = hashlib.sha256(key.encode()).digest()[:16]
    iv = data[:16]
    data = data[16:]

    plain = b""
    prev = iv
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        # mock AES block decrypt (same as encrypt in mock)
        decrypted = hashlib.sha256(xor_bytes(block, key_bytes)).digest()[:16]
        plain_block = xor_bytes(block, prev)  # simulate CBC
        plain += plain_block
        prev = block
    return unpad(plain)