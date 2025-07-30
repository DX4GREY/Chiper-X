import argparse
import os
from crypt_tools.crypt import (
    encrypt_file, decrypt_file,
    EncryptionError, DecryptionError,
    encrypt_data, decrypt_data
)

def parse_pattern_file(pattern_file: str) -> tuple[str, list[str]]:
    if not os.path.isfile(pattern_file):
        raise FileNotFoundError(f"Pattern file not found: {pattern_file}")
    with open(pattern_file, 'r') as f:
        line = f.readline().strip()
        if ':' not in line:
            raise ValueError("Invalid pattern format. Use: key:AXXA")
        key, pattern = line.split(':', 1)
        return key, list(pattern.upper())

def encrypt_with_pattern(data: bytes, pattern: list[str], key: str) -> bytes:
    for method in pattern:
        if method == 'A':
            data = encrypt_data('aes', data, key)
        elif method == 'X':
            data = encrypt_data('xor', data, key)
        else:
            raise EncryptionError(f"Unknown pattern method: {method}")
    return data

def decrypt_with_pattern(data: bytes, pattern: list[str], key: str) -> bytes:
    for method in reversed(pattern):
        if method == 'A':
            data = decrypt_data('aes', data, key)
        elif method == 'X':
            data = decrypt_data('xor', data, key)
        else:
            raise DecryptionError(f"Unknown pattern method: {method}")
    return data

def main():
    parser = argparse.ArgumentParser(description="xor-tool: file encrypter/decrypter using XOR or AES.")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode: encrypt or decrypt")
    parser.add_argument("input", help="Input file path")
    parser.add_argument("output", help="Output file path")
    parser.add_argument("--key", help="Encryption key (string)")
    parser.add_argument("--method", choices=["xor", "aes"], help="Encryption method")
    parser.add_argument("--pattern", help="Pattern file path (e.g., pattern.txt)")

    args = parser.parse_args()

    try:
        with open(args.input, 'rb') as f:
            data = f.read()

        if args.pattern:
            key, pattern = parse_pattern_file(args.pattern)
            if args.mode == "encrypt":
                result = encrypt_with_pattern(data, pattern, key)
            else:
                result = decrypt_with_pattern(data, pattern, key)
        else:
            if not args.key or not args.method:
                raise ValueError("If --pattern not used, --key and --method are required")
            if args.mode == "encrypt":
                encrypt_file(args.method, args.input, args.output, args.key)
                return
            else:
                decrypt_file(args.method, args.input, args.output, args.key)
                return

        with open(args.output, 'wb') as f:
            f.write(result)
        print(f"{args.mode.title()}ion complete: {args.output}")

    except (EncryptionError, DecryptionError, Exception) as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()