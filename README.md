# Windows 11 Start Menu `start2.bin` File Format and Cryptographic Specification

> A complete, self-contained reference describing how the Windows 11 Start Menu
> persistence file (`start2.bin`) is encrypted, framed, and validated.
> All values were recovered from static analysis of `StartMenu.dll` v2126.5401.10.0
> (Windows 11, x64) and confirmed against live files. No proprietary tooling,
> external project, or auxiliary script is required to read this document.

> 📄 繁體中文版：[README.zh_TW.md](./README.zh_TW.md)

---

## Table of Contents

1. [Background](#1-background)
2. [Locations on Disk](#2-locations-on-disk)
3. [File Layout](#3-file-layout)
4. [Cryptographic Constants](#4-cryptographic-constants)
5. [Mersenne Twister (MT19937) Engine](#5-mersenne-twister-mt19937-engine)
6. [Key/IV Generation](#6-keyiv-generation)
7. [AES Encryption](#7-aes-encryption)
8. [Decryption Procedure](#8-decryption-procedure)
9. [Encryption Procedure](#9-encryption-procedure)
10. [Worked Example](#10-worked-example)
11. [Reference Python Implementation](#11-reference-python-implementation)
12. [Constant Quick Reference](#12-constant-quick-reference)

---

## 1. Background

The Windows 11 Start Menu host process (`StartMenuExperienceHost.exe`) loads
`StartMenu.dll`, which serialises pinned tiles, recently launched applications,
and similar UI state into a single binary file named `start2.bin`.

Inside the DLL the responsible namespace is `SlimObfuscationManager`, with
helper class `StableCryptoFunctions`. The on-disk format is:

```
┌─────────────────────────────────┐ ← 0x00
│  MAGIC (16 bytes)               │
├─────────────────────────────────┤ ← 0x10
│  HEADER_CONST (16 bytes)        │
├─────────────────────────────────┤ ← 0x20
│  FILETIME (8 bytes)             │
├─────────────────────────────────┤ ← 0x28
│  total_payload_length (4 bytes) │
├─────────────────────────────────┤ ← 0x2C
│  pre-padding  (N bytes)         │  ← random; N = pad_mt() & 0x1FF (0..511)
├─────────────────────────────────┤
│  AES-256-CBC ciphertext         │  ← total_payload_length − 0x200 bytes
├─────────────────────────────────┤
│  post-padding (0x200−N bytes)   │  ← random; complement of pre, NOT another 512
└─────────────────────────────────┘
```

The file is encrypted with **AES-256-CBC + PKCS#7 padding**. The 256-bit key
and 128-bit IV are derived from two independent **MT19937** PRNGs, each seeded
from the file's own `FILETIME` field combined with two embedded constants.

Because the seed material is stored in plaintext inside the file header, any
reader can reproduce the keys deterministically; the construction is therefore
properly described as **obfuscation**, not authenticated encryption.

---

## 2. Locations on Disk

```
%LocalAppData%\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\
    start2.bin
```

Both files are written atomically by the Start Menu host whenever the user
pins, unpins, or rearranges tiles.

---

## 3. File Layout

All multi-byte integer fields are **little-endian**.

| Offset | Size      | Field                  | Description                                              |
|-------:|----------:|------------------------|----------------------------------------------------------|
| `0x00` | 16 B      | `MAGIC`                | Fixed GUID, serialised in WinRT `WriteGuid` byte order   |
| `0x10` | 16 B      | `HEADER_CONST`         | Fixed 16-byte constant, written verbatim                 |
| `0x20` | 4 B       | `FILETIME.dwLowDateTime`  | Lower 32 bits of `GetSystemTimeAsFileTime()`          |
| `0x24` | 4 B       | `FILETIME.dwHighDateTime` | Upper 32 bits of `GetSystemTimeAsFileTime()`          |
| `0x28` | 4 B       | `total_payload_length` | `ciphertext_len + 0x200`                                 |
| `0x2C` | `N` B     | pre-padding            | Random bytes, `N = pad_mt() & 0x1FF` (0..511)            |
| `0x2C+N` | `M` B   | ciphertext             | `M = total_payload_length − 0x200`                       |
| `0x2C+N+M` | `0x200−N` B | post-padding     | Random bytes, total padding always = 512                 |

### 3.1 `MAGIC` byte representation

In the DLL's image the GUID is stored as a standard `GUID` struct
(`{E27AE14B-01FC-4D1B-8551-6EDE0B81009C}`), i.e. in memory:

```
4B E1 7A E2  FC 01  1B 4D  85 51  6E DE 0B 81 00 9C
└── Data1 ──┘ Data2 Data3 └─────── Data4 ────────┘
```

The runtime writes it via `IDataWriter::WriteGuid`, which serialises each
`Data1`/`Data2`/`Data3` component in **big-endian** order:

```
on disk:  E2 7A E1 4B  01 FC  4D 1B  85 51 6E DE 0B 81 00 9C
                                     └────── Data4 raw ──────┘
```

Note that `Data4`'s 8 bytes are written as-is (no reversal) because they are
defined as a byte array, but the WinRT serialiser also appears to byte-swap
the high/low halves of `Data4` in some test vectors. Programs that need to
verify the magic should compare against the **on-disk byte sequence** below,
not the GUID struct:

```
E2 7A E1 4B 01 FC 4D 1B 9C 00 81 0B DE 6E 51 85
```

### 3.2 `HEADER_CONST`

A second fixed constant follows the magic. It is initialised on the stack as
four little-endian DWORDs and written by `IDataWriter::WriteBytes`, so the
on-disk bytes match the in-memory bytes exactly:

```
DWORD[0] = 0x475F5A4E   →  4E 5A 5F 47
DWORD[1] = 0x49B15B00   →  00 5B B1 49
DWORD[2] = 0xAF925C8A   →  8A 5C 92 AF
DWORD[3] = 0x5EF98490   →  90 84 F9 5E

on disk:  4E 5A 5F 47 00 5B B1 49 8A 5C 92 AF 90 84 F9 5E
```

The constant has no documented meaning; treat it as an opaque magic.

### 3.3 Padding accounting

Total padding (pre + post) is always **0x200 (512)** bytes — the two regions
share a fixed budget; they are not each independently 512. The split point
`N = pad_mt() & 0x1FF` gives pre-padding in [0, 511] bytes, and the
remainder `0x200 − N` (1..512 bytes) becomes post-padding. Only the split
varies per file. This means the file size is always:

```
file_size = 0x2C + 0x200 + ciphertext_len
          = total_payload_length + 0x2C
```

---

## 4. Cryptographic Constants

Two 32-bit constants are embedded in the encryption provider:

| Name           | Value         | Role                                                        |
|----------------|---------------|-------------------------------------------------------------|
| `PROV_KEY_DW0` | `0x3B21D91E`  | XOR'd into the key/IV MT seed                               |
| `PROV_KEY_DW1` | `0x4D9700AF`  | Source for the padding-MT seed constant                     |
| `PROV_KEY_DW2` | `0x8E2AB4AA`  | Allocated but unused on the cryptographic path              |
| `PROV_KEY_DW3` | `0xEAA91EA8`  | Allocated but unused on the cryptographic path              |

A derived constant is computed once per encrypt/decrypt:

```
PAD_SEED_CONST = ((PROV_KEY_DW1 & 0xFFFF) << 16)
               |  (PROV_KEY_DW1 >> 16)
               =  0x00AF4D97
```

Equivalently: swap the high and low 16-bit halves of `PROV_KEY_DW1`.

---

## 5. Mersenne Twister (MT19937) Engine

The file format uses the **standard 32-bit Mersenne Twister** (the same engine
exposed by C++ `std::mt19937`). All template parameters were verified against
the binary:

| Parameter            | Value         |
|----------------------|---------------|
| word size            | 32            |
| state size (N)       | 624           |
| shift size (M)       | 397           |
| mask bits            | 31            |
| `MATRIX_A`           | `0x9908B0DF`  |
| tempering `u`        | 11            |
| tempering `d`        | `0xFFFFFFFF`  |
| tempering `s`        | 7             |
| tempering `b`        | `0x9D2C5680`  |
| tempering `t`        | 15            |
| tempering `c`        | `0xEFC60000`  |
| tempering `l`        | 18            |
| init multiplier `f`  | `0x6C078965`  |

### 5.1 Seeding

Standard C++11 seeding:

```c
state[0] = seed;
for (i = 1; i < 624; i++)
    state[i] = (state[i-1] ^ (state[i-1] >> 30)) * 0x6C078965 + i;
```

### 5.2 Output (`operator()`)

Standard tempering — see any reference C++ implementation. The constants above
are sufficient to reproduce it bit-for-bit.

---

## 6. Key/IV Generation

### 6.1 Two independent MT instances

Each file uses two MT19937 streams, each seeded from the file's own
`FILETIME`:

```
pad_seed = PAD_SEED_CONST  ^  FILETIME.dwLowDateTime
         = 0x00AF4D97      ^  ft_low

sym_seed = FILETIME.dwHighDateTime  ^  FILETIME.dwLowDateTime  ^  PROV_KEY_DW0
         = ft_high                  ^  ft_low                   ^  0x3B21D91E
```

`pad_mt = MT19937(pad_seed)` is used for:
1. The **first output** ANDed with `0x1FF` gives `pre_pad_len` (0..511).
2. Subsequent outputs (truncated to a byte each) fill pre/post padding bytes.

`sym_mt = MT19937(sym_seed)` is consumed by `GetSymmetricKeys` (below).

### 6.2 `GetSymmetricKeys(sym_seed)`

Constants in this routine are: `MIN = 0x40 (64)`, `MAX = 0x80 (128)`,
`IV_LEN = 0x10 (16)`.

```
mt        = MT19937(sym_seed)
key_seed  = mt()                                  // 1st output
key_len   = MIN + uniform_uint(mt, MAX - MIN)      // 2nd output (rejection)
iv_seed   = mt()                                  // 3rd output

key_str   = AlphaNumericKeyGenerator(key_seed, key_len)   // 64..128 chars
iv_str    = AlphaNumericKeyGenerator(iv_seed,  IV_LEN)    // 16 chars
```

### 6.3 `uniform_uint(mt, range_size)` — rejection sampling

This is the algorithm produced by C++ `std::uniform_int_distribution<unsigned>`
(libc++/MSVC implementation):

```c
if (range_size == 0)            return 0;
if (range_size == 0xFFFFFFFF)   return mt();

bound = range_size + 1;
while (true) {
    v = mt();
    // accept v if it does NOT fall in the truncated tail
    if (!((0xFFFFFFFF / bound) <= (v / bound)
       && (0xFFFFFFFF % bound) != range_size))
        return v % bound;
}
```

For `range_size = 0x40` the rejection rate is `≈ 1.56%`, so on average just
over one `mt()` call is consumed.

### 6.4 `AlphaNumericKeyGenerator(seed, length)`

A second MT is constructed from `seed`, advanced by a randomised offset, then
used to produce printable ASCII characters:

```c
mt = MT19937(seed)

// Phase 1: warm-up — discard a variable number of outputs
do {
    v = mt();
} while ((v / 0x3E9) > 0x417873);     // 0x3E9 = 1001
mt.discard(v % 0x3E9);                  // discard 0..1000 outputs

// Phase 2: produce `length` printable characters in [0x20, 0x7F]
for (i = 0; i < length; i++) {
    do {
        v = mt();
    } while ((v / 0x60) > 0x2AAAAA9);  // 0x60 = 96
    out[i] = (uint16_t)((v % 0x60) + 0x20);
}
```

Both rejection loops accept on the very first attempt with overwhelming
probability (`≈ 1.6%` and `≈ 0.16%` rejection respectively).

The buffer `out` is a `wchar_t` (UTF-16) string — but every character is in
`[0x20, 0x7F]` (printable ASCII, including `0x7F`/DEL).

### 6.5 String → byte buffer

The wchar_t key/IV strings are passed to
`Windows.Security.Cryptography.CryptographicBuffer.ConvertStringToBinary`
with `BinaryStringEncoding = 0` (**Utf8**).

Because every character is plain ASCII, UTF-8 encoding produces **one byte
per character** with values identical to the character codes themselves.
Net effect:

* `key_buf` is `key_len` bytes long, each in `[0x20, 0x7F]`. Length is between
  64 and 128 bytes.
* `iv_buf` is exactly 16 bytes long, each in `[0x20, 0x7F]`.

---

## 7. AES Encryption

* Algorithm string passed to
  `SymmetricKeyAlgorithmProvider::OpenAlgorithm`: **`"AES_CBC_PKCS7"`**.
* `CreateSymmetricKey` is invoked with the full `key_buf` (64..128 bytes).
  Windows CNG (BCrypt under the hood) selects the **largest AES key size that
  fits** — i.e. **AES-256** — and silently uses only the **first 32 bytes**
  of the buffer. The remaining bytes are ignored.
* The IV is the full 16-byte `iv_buf`.
* PKCS#7 padding is applied automatically.

In other words the scheme is exactly:

```
ciphertext = AES_256_CBC_PKCS7_Encrypt(plaintext, key_buf[:32], iv_buf)
```

This was verified empirically: AES-128 (using `key_buf[:16]`) fails with a
PKCS#7 padding error on real files; AES-256 with `key_buf[:32]` decrypts
cleanly to a JSON document.

---

## 8. Decryption Procedure

Given a `start2.bin`:

```
 1. Read first 16 bytes; verify they equal MAGIC (on-disk byte form, §3.1).
 2. Read bytes [0x10:0x20]; verify they equal HEADER_CONST.
 3. Read ft_low = u32_le @ 0x20 ;  ft_high = u32_le @ 0x24
 4. Read total_len = u32_le @ 0x28
 5. ciphertext_len = total_len − 0x200          ; must be ≥ 0 and a multiple of 16

 6. pad_seed   = 0x00AF4D97 ^ ft_low
    pad_mt     = MT19937(pad_seed)
    pre_pad    = pad_mt() & 0x1FF              ; first output only
    cipher_off = 0x2C + pre_pad
    ciphertext = data[cipher_off : cipher_off + ciphertext_len]

 7. sym_seed   = ft_high ^ ft_low ^ 0x3B21D91E
    (key_buf, iv_buf) = GetSymmetricKeys(sym_seed)

 8. plaintext = AES_256_CBC_PKCS7_Decrypt(ciphertext, key_buf[:32], iv_buf)
```

The plaintext is a UTF-8 JSON document (`{ ... }`) describing the user's
pinned-tile state.

---

## 9. Encryption Procedure

To produce a `start2.bin` from a JSON plaintext:

```
 1. ft = GetSystemTimeAsFileTime()             ; or any 64-bit value
 2. pad_seed = 0x00AF4D97 ^ ft.low
    pad_mt    = MT19937(pad_seed)
    pre_pad   = pad_mt() & 0x1FF
    post_pad  = 0x200 − pre_pad
 3. sym_seed = ft.high ^ ft.low ^ 0x3B21D91E
    (key_buf, iv_buf) = GetSymmetricKeys(sym_seed)
 4. ciphertext = AES_256_CBC_PKCS7_Encrypt(plaintext, key_buf[:32], iv_buf)
 5. total_len = len(ciphertext) + 0x200

 6. Emit:
      MAGIC            (16 bytes, on-disk byte form)
      HEADER_CONST     (16 bytes)
      ft.low           (4 bytes, LE)
      ft.high          (4 bytes, LE)
      total_len        (4 bytes, LE)
      pre_pad bytes    drawn from pad_mt() & 0xFF
      ciphertext       (total_len − 0x200 bytes)
      post_pad bytes   drawn from pad_mt() & 0xFF
```

The padding bytes are output one at a time using subsequent `pad_mt()` calls
truncated to a byte. Their values are not checked on read, so any random
source is acceptable; the original implementation simply continues with the
same MT instance.

---

## 10. Worked Example

A real `start2.bin` file with the following header bytes:

```
0x00:  E2 7A E1 4B 01 FC 4D 1B 9C 00 81 0B DE 6E 51 85   ; MAGIC      ✓
0x10:  4E 5A 5F 47 00 5B B1 49 8A 5C 92 AF 90 84 F9 5E   ; HEADER     ✓
0x20:  17 D5 1D BC EF D4 DC 01                            ; FILETIME
0x28:  90 3D 00 00                                        ; total_len = 0x3D90 = 15760
```

Derivations:

```
ft_low      = 0xBC1DD517
ft_high     = 0x01DCD4EF

pad_seed    = 0x00AF4D97 ^ 0xBC1DD517 = 0xBCB29880
pad_mt      = MT19937(0xBCB29880)
pre_pad     = pad_mt() & 0x1FF = 294 (decimal)
post_pad    = 512 − 294 = 218

ciphertext_len = 0x3D90 − 0x200 = 0x3B90 = 15248
cipher_off     = 0x2C + 294 = 0x152

sym_seed    = 0x01DCD4EF ^ 0xBC1DD517 ^ 0x3B21D91E = 0x86E0D8E6
              ^ note: any seed value is valid; this is the example file's value
(key_buf, iv_buf) = GetSymmetricKeys(0x86E0D8E6)
                  → key_buf = b"FplVt'UjdEX\\hi\\oK'(+~c5$i%T++xZ&=GT~28..."   (105 bytes)
                  → iv_buf  = b'_9AFrlIN9CCr"Ynn'                              (16 bytes)

plaintext   = AES_256_CBC_PKCS7_Decrypt(
                ciphertext      = data[0x152 : 0x152 + 15248],
                key             = key_buf[:32],
                iv              = iv_buf,
              )
            → b'{ "...": ... }'    (UTF-8 JSON)
```

Note that `key_len` happens to be 105 here; for any other file it would land
somewhere in `[64, 128]` according to the second MT output.

---

## 11. Reference Python Implementation

This complete script reads any `start2.bin` and prints its plaintext JSON.
It depends only on the Python standard library plus the `cryptography`
package (`pip install cryptography`).

```python
#!/usr/bin/env python3
"""Decrypt a Windows 11 Start Menu start2.bin file."""

import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# --- MT19937 (matches std::mt19937 / C++11 mersenne_twister_engine<uint32_t,...>) ---
class MT19937:
    N, M = 624, 397
    MATRIX_A    = 0x9908B0DF
    UPPER_MASK  = 0x80000000
    LOWER_MASK  = 0x7FFFFFFF
    MASK32      = 0xFFFFFFFF

    def __init__(self, seed):
        s = seed & self.MASK32
        self.mt = [s]
        for i in range(1, self.N):
            s = (1812433253 * (s ^ (s >> 30)) + i) & self.MASK32
            self.mt.append(s)
        self.index = self.N

    def _generate(self):
        for i in range(self.N):
            y = (self.mt[i] & self.UPPER_MASK) | (self.mt[(i + 1) % self.N] & self.LOWER_MASK)
            self.mt[i] = self.mt[(i + self.M) % self.N] ^ (y >> 1)
            if y & 1:
                self.mt[i] ^= self.MATRIX_A
        self.index = 0

    def __call__(self):
        if self.index >= self.N:
            self._generate()
        y = self.mt[self.index]
        self.index += 1
        y ^=  y >> 11
        y ^= (y <<  7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^=  y >> 18
        return y & self.MASK32

    def discard(self, n):
        for _ in range(n):
            self()


# --- uniform_int_distribution<unsigned int> (rejection sampling) ---
def uniform_uint(mt, range_size):
    if range_size == 0:
        return 0
    if range_size == 0xFFFFFFFF:
        return mt()
    bound = range_size + 1
    while True:
        v = mt()
        if not ((0xFFFFFFFF // bound) <= (v // bound)
            and (0xFFFFFFFF %  bound) != range_size):
            return v % bound


# --- AlphaNumericKeyGenerator(seed, length) -> 8-bit ASCII bytes ---
def alpha_numeric_key(seed, length):
    mt = MT19937(seed)
    while True:
        v = mt()
        if v // 0x3E9 <= 0x417873:
            break
    mt.discard(v % 0x3E9)

    out = bytearray()
    for _ in range(length):
        while True:
            v = mt()
            if v // 0x60 <= 0x2AAAAA9:
                break
        out.append((v % 0x60) + 0x20)
    return bytes(out)


# --- GetSymmetricKeys(sym_seed) -> (key_buf, iv_buf) ---
def get_symmetric_keys(sym_seed, *, mn=0x40, mx=0x80, iv_len=0x10):
    mt        = MT19937(sym_seed)
    key_seed  = mt()
    key_len   = mn + uniform_uint(mt, mx - mn)
    iv_seed   = mt()
    return alpha_numeric_key(key_seed, key_len), alpha_numeric_key(iv_seed, iv_len)


MAGIC        = bytes.fromhex("E27AE14B01FC4D1B9C00810BDE6E5185")
HEADER_CONST = bytes.fromhex("4E5A5F47005BB1498A5C92AF9084F95E")


def decrypt(path):
    data = Path(path).read_bytes()

    assert data[0x00:0x10] == MAGIC,        "bad MAGIC"
    assert data[0x10:0x20] == HEADER_CONST, "bad HEADER_CONST"

    ft_low, ft_high, total_len = struct.unpack_from("<III", data, 0x20)
    cipher_len  = total_len - 0x200
    pad_mt      = MT19937(0x00AF4D97 ^ ft_low)
    pre_pad     = pad_mt() & 0x1FF
    cipher_off  = 0x2C + pre_pad
    ciphertext  = data[cipher_off:cipher_off + cipher_len]

    sym_seed    = ft_high ^ ft_low ^ 0x3B21D91E
    key_buf, iv_buf = get_symmetric_keys(sym_seed)

    cipher  = Cipher(algorithms.AES(key_buf[:32]), modes.CBC(iv_buf))
    padded  = cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize()
    pad_len = padded[-1]
    return padded[:-pad_len]


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: decrypt_start2.py <path-to-start2.bin>")
    sys.stdout.buffer.write(decrypt(sys.argv[1]))
```

The script assumes the input file is well-formed and fails fast otherwise.
For production use, replace `assert` with explicit error handling and add
defensive checks on `total_len`, `cipher_len`, and `pre_pad`.

---

## 12. Constant Quick Reference

| Name                          | Value                                                    |
|-------------------------------|----------------------------------------------------------|
| `MAGIC` (on disk)             | `E2 7A E1 4B 01 FC 4D 1B 9C 00 81 0B DE 6E 51 85`        |
| `MAGIC` (GUID struct in DLL)  | `4B E1 7A E2 FC 01 1B 4D 85 51 6E DE 0B 81 00 9C`        |
| `MAGIC` (canonical form)      | `{E27AE14B-01FC-4D1B-8551-6EDE0B81009C}`                 |
| `HEADER_CONST`                | `4E 5A 5F 47 00 5B B1 49 8A 5C 92 AF 90 84 F9 5E`        |
| `PROV_KEY_DW0`                | `0x3B21D91E`                                             |
| `PROV_KEY_DW1`                | `0x4D9700AF`                                             |
| `PROV_KEY_DW2` (unused)       | `0x8E2AB4AA`                                             |
| `PROV_KEY_DW3` (unused)       | `0xEAA91EA8`                                             |
| `PAD_SEED_CONST`              | `0x00AF4D97`                                             |
| `MIN_KEY_LEN`                 | `0x40` (64 chars / 64 bytes after UTF-8 encoding)        |
| `MAX_KEY_LEN`                 | `0x80` (128 chars / 128 bytes after UTF-8 encoding)      |
| `AES_KEY_LEN`                 | `0x20` (32 bytes — AES-256, taken from `key_buf[:32]`)   |
| `AES_BLOCK_SIZE`              | `0x10` (16 bytes — IV length and CBC block size)         |
| `PAYLOAD_PAD_TOTAL`           | `0x200` (512 — pre + post padding bytes per file)        |
| Algorithm string              | `"AES_CBC_PKCS7"`                                        |
| AlphaNumeric char range       | `[0x20, 0x7F]` (96 distinct printable ASCII values)      |
| Phase-1 reject threshold      | `v / 0x3E9 > 0x417873`                                   |
| Phase-2 reject threshold      | `v / 0x60  > 0x2AAAAA9`                                  |
| MT19937 init multiplier `f`   | `0x6C078965`                                             |
| MT19937 `MATRIX_A`            | `0x9908B0DF`                                             |

---

### End of Specification

Everything above is sufficient to read, validate, and write `start2.bin`
files byte-for-byte without any other reference. There are no hidden steps,
authentication tags, or version-dependent branches in the cryptographic
path: the same algorithm has been observed across all builds inspected.
