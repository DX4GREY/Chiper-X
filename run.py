import argparse, os, traceback
from crypt_tools.crypt import (
    encrypt_file, decrypt_file,
    EncryptionError, DecryptionError,
    encrypt_data, decrypt_data
)
global output_file

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
        elif method == 'V':
            data = encrypt_data('vigenere', data, key)
        elif method == 'R':
            data = encrypt_data('rc4', data, key)
        elif method == 'C':
            data = encrypt_data('vichaos', data, key)
        else:
            raise EncryptionError(f"Unknown pattern method: {method}")
    return data

def decrypt_with_pattern(data: bytes, pattern: list[str], key: str) -> bytes:
    for method in reversed(pattern):
        if method == 'A':
            data = decrypt_data('aes', data, key)
        elif method == 'X':
            data = decrypt_data('xor', data, key)
        elif method == 'V':
            data = decrypt_data('vigenere', data, key)
        elif method == 'R':
            data = decrypt_data('rc4', data, key)
        elif method == 'C':
            data = decrypt_data('vichaos', data, key)
        else:
            raise DecryptionError(f"Unknown pattern method: {method}")
    return data

def process_directory(input_dir: str, key: str, pattern: list[str] = None, method: str = None, mode: str = "encrypt"):
    output_root = f"{os.path.basename(os.path.abspath(input_dir))}"
    for root, _, files in os.walk(input_dir):
        for file in files:
            in_path = os.path.join(root, file)
            rel_path = os.path.relpath(in_path, input_dir)
            out_path = os.path.join(output_root, rel_path)

            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(in_path, 'rb') as f:
                data = f.read()
            try:
                if pattern:
                    if mode == "encrypt":
                        result = encrypt_with_pattern(data, pattern, key)
                    else:
                        result = decrypt_with_pattern(data, pattern, key)
                else:
                    if mode == "encrypt":
                        result = encrypt_data(method, data, key)
                    else:
                        result = decrypt_data(method, data, key)
                with open(out_path, 'wb') as f:
                    f.write(result)
                print(f"{mode.title()}ed: {in_path} -> {out_path}")
            except Exception as e:
                print(f"Failed to process {in_path}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Chiper-X: file encrypter/decrypter using XOR, AES, Vigenère, RC4, or ViChaos.")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode: encrypt or decrypt")
    parser.add_argument("input", help="Input file or directory")
    parser.add_argument("output", nargs='?', help="Output file (for single file only)")
    parser.add_argument("--key", help="Encryption key (string)")
    parser.add_argument("--method", choices=["xor", "aes", "vigenere", "rc4", "vichaos"], help="Encryption method")
    parser.add_argument("--pattern", help="Pattern file path (e.g., chiper-x.pattern)")

    args = parser.parse_args()

    try:
        if os.path.isdir(args.input):
            if args.pattern:
                key, pattern = parse_pattern_file(args.pattern)
                process_directory(args.input, key, pattern=pattern, mode=args.mode)
            else:
                if not args.key or not args.method:
                    raise ValueError("If --pattern not used, --key and --method are required")
                process_directory(args.input, args.key, method=args.method, mode=args.mode)
            print(f"{args.mode.title()}ion complete for directory: {args.input}")
            return

        # File tunggal
        with open(args.input, 'rb') as f:
            data = f.read()
        output_file = args.output if args.output else args.input
        
        if args.pattern:
            key, pattern = parse_pattern_file(args.pattern)
            if args.mode == "encrypt":
                result = encrypt_with_pattern(data, pattern, key)
            else:
                result = decrypt_with_pattern(data, pattern, key)
            with open(output_file, 'wb') as f:
                f.write(result)
        else:
            if not args.key or not args.method:
                raise ValueError("If --pattern not used, --key and --method are required")
            
            if args.mode == "encrypt":
                encrypt_file(args.method, args.input, output_file, args.key)
            else:
                decrypt_file(args.method, args.input, output_file, args.key)
                
        print(f"{args.mode.title()}ion complete: {output_file}")

    except (EncryptionError, DecryptionError, Exception, ValueError) as e:
        print(f"Error: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    main()