# xor-tool (by Awang & Joni) 🔐

## 📄 Description

**xor-tool** is a simple CLI tool to encrypt or decrypt files using:

* XOR cipher (basic and lightweight)
* AES-CBC (requires `pycryptodome`)
* Or a custom pattern like `AXAXXA` combining both — great for experimenting with layered encryption.

---

## 🚀 Usage

```
xor-tool [encrypt|decrypt] <input_file> <output_file> 
         --key YOUR_KEY [--aes]
         [--pattern pattern.txt]
```

---

## ⚙️ Options

* `--key` → Required (unless using `--pattern`). The key for encryption/decryption.
* `--aes` → Optional. Enables AES-CBC instead of XOR.
* `--pattern` → Optional. Path to a pattern file with format: `KEY:PATTERN`
  Example:

  ```
  mysecretkey:AXXAAX
  ```

---

## 🧪 Examples

### XOR Encryption

```
xor-tool encrypt secret.txt secret.enc --key hello123
```

### XOR Decryption

```
xor-tool decrypt secret.enc secret-decrypted.txt --key hello123
```

### AES Encryption (requires pycryptodome)

```
xor-tool encrypt file.txt file.aes --key mysecurekey --aes
```

### AES Decryption

```
xor-tool decrypt file.aes output.txt --key mysecurekey --aes
```

### Pattern-Based Encryption

```
xor-tool encrypt input.txt encrypted.bin --pattern pattern.txt
```

### Pattern-Based Decryption

```
xor-tool decrypt encrypted.bin output.txt --pattern pattern.txt
```

Example `pattern.txt` content:

```
mysecretkey:AXAXXA
```

---

## 📝 Notes

* If `--pattern` is used, both `--key` and `--aes` are ignored.
* AES keys are padded or truncated to 32 bytes.
* The AES IV is automatically prepended to the encrypted file.
* Pattern supports any mix of `A` (AES) and `X` (XOR).
* XOR is not secure for real-world usage — it's for educational/testing purposes.
* AES will be disabled automatically if `pycryptodome` is not installed.

---

## 🔗 License

MIT — free to use, modify, and share 🙌