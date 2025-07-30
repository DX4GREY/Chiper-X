## 🔐 Chiper-X (by Dx4Grey)

## Description

**Chiper-X** is a CLI utility to encrypt or decrypt **files or entire directories** using:

* **XOR** cipher (lightweight)
* **AES-CBC**
* **Vigenère**
* **RC4**
* **ViChaos** (custom layered algorithm with pseudo-chaotic transformation)
* Or a **custom pattern** like `AXVRC` combining multiple algorithms in sequence — ideal for testing layered encryption approaches.

---

## Usage

```
chiper-x [encrypt|decrypt] <input> [output] 
         [--key YOUR_KEY]
         [--method xor|aes|vigenere|rc4|vichaos]
         [--pattern pattern.txt]
```

> 🔹 `input` can be a **file or directory**
> 🔹 `output` is **optional** when processing a file — will overwrite `input` if omitted
> 🔹 When using `--pattern`, `--key` and `--method` are ignored

---

## Options

| Option      | Description                                                                             |
| ----------- | --------------------------------------------------------------------------------------- |
| `--key`     | Required (unless using `--pattern`). The encryption key as a string.                    |
| `--method`  | One of: `xor`, `aes`, `vigenere`, `rc4`, `vichaos`. Required if `--pattern` is not set. |
| `--pattern` | Path to pattern file: `key:PATTERN` (e.g., `mykey:AXVRC`)                                |

---

## Supported Methods

| Symbol | Method   |
| ------ | -------- |
| `A`    | AES-CBC  |
| `X`    | XOR      |
| `V`    | Vigenère |
| `R`    | RC4      |
| `C`    | ViChaos  |

> `C` = ViChaos (word from "chaos")

---

## Examples

### XOR Encryption (Single File)

```
chiper-x encrypt secret.txt secret.enc --key hello123 --method xor
```

### ViChaos Encryption

```
chiper-x encrypt file.txt file.enc --key mychaoskey --method vichaos
```

### Pattern-Based Encryption

Given `pattern.txt`:

```
superkey:AXVRC
```

Encrypt with layered methods:

```
chiper-x encrypt input.txt encrypted.bin --pattern pattern.txt
```

And decrypt:

```
chiper-x decrypt encrypted.bin --pattern pattern.txt
```

### Directory Encryption

```
chiper-x encrypt myfolder --key topsecret --method vichaos
```

Will encrypt all files and save to `myfolder/` (overwritten structure).

---

## Notes

* If `--pattern` is used, `--key` and `--method` are **ignored**
* AES uses CBC mode with a random IV prepended to the file
* Keys are padded/truncated depending on algorithm:

  * AES: 16–32 bytes
  * XOR/Vigenère/RC4/ViChaos: no strict length
* Directory input replicates folder structure in output
* `--output` is **only valid for file input**, not directories
* If `--output` is omitted for files, it will **overwrite input**

---

## Requirements

* Python 3.6+

---

## License

MIT — free to use, modify, and share.