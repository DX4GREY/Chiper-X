# 🔐 xor-tool (by Dx4Grey)

## 📄 Description

**xor-tool** is a CLI utility to encrypt or decrypt **files or entire directories** using:

* **XOR** cipher (lightweight)
* **AES-CBC** (via `pycryptodome`)
* **Vigenère**
* **RC4**
* Or a **custom pattern** like `AXVR` combining multiple algorithms in sequence — ideal for testing layered encryption approaches.

---

## 🚀 Usage

```
xor-tool [encrypt|decrypt] <input> [output] 
         [--key YOUR_KEY]
         [--method xor|aes|vigenere|rc4]
         [--pattern pattern.txt]
```

> 🔹 `input` can be a **file or directory**
> 🔹 `output` is **optional** when processing a file — will overwrite `input` if omitted
> 🔹 When using `--pattern`, `--key` and `--method` are ignored

---

## ⚙️ Options

| Option      | Description                                                                  |
| ----------- | ---------------------------------------------------------------------------- |
| `--key`     | Required (unless using `--pattern`). The encryption key as a string.         |
| `--method`  | One of: `xor`, `aes`, `vigenere`, `rc4`. Required if `--pattern` is not set. |
| `--pattern` | Path to pattern file: `key:PATTERN` (e.g., `mykey:AXVR`)                     |

---

## 🔄 Supported Methods

| Symbol | Method   |
| ------ | -------- |
| `A`    | AES-CBC  |
| `X`    | XOR      |
| `V`    | Vigenère |
| `R`    | RC4      |

---

## 🧪 Examples

### XOR Encryption (Single File)

```
xor-tool encrypt secret.txt secret.enc --key hello123 --method xor
```

### XOR Decryption (Overwrite original)

```
xor-tool decrypt secret.enc --key hello123 --method xor
```

### AES Encryption (requires `pycryptodome`)

```
xor-tool encrypt file.txt aes.enc --key securekey --method aes
```

### Pattern-Based Encryption

Given `pattern.txt`:

```
superkey:AXVR
```

Encrypt with layered methods:

```
xor-tool encrypt input.txt encrypted.bin --pattern pattern.txt
```

And decrypt:

```
xor-tool decrypt encrypted.bin --pattern pattern.txt
```

### Directory Encryption

```
xor-tool encrypt myfolder --key topsecret --method vigenere
```

Will encrypt all files and save to `myfolder/` (overwritten structure).

---

## 📝 Notes

* If `--pattern` is used, `--key` and `--method` are **ignored**
* AES uses CBC mode with a random IV prepended to the file
* Keys are padded/truncated depending on algorithm:

  * AES: 16–32 bytes
  * XOR/Vigenère/RC4: no strict length
* Directory input replicates folder structure in output
* `--output` is **only valid for file input**, not directories
* If `--output` is omitted for files, it will **overwrite input**

---

## 🔧 Requirements

* Python 3.6+
* `pycryptodome` (for AES support):

```bash
pip install pycryptodome
```

---

## 🔗 License

MIT — free to use, modify, and share 🙌