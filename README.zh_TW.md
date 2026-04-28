# Windows 11 開始功能表 `start2.bin` 檔案格式與加密規格

> 本文件完整且自洽地說明 Windows 11 開始功能表持久化檔案（`start2.bin`）的加密方式、框架結構與驗證方法。
> 所有數值均由靜態分析 `StartMenu.dll` v2126.5401.10.0（Windows 11, x64）取得，並經由實際檔案比對確認。
> 閱讀本文件不需要任何專屬工具、外部專案或輔助腳本。

> 📄 English version: [README.md](./README.md)

---

## 目錄

1. [背景](#1-背景)
2. [磁碟路徑](#2-磁碟路徑)
3. [檔案佈局](#3-檔案佈局)
4. [密碼學常數](#4-密碼學常數)
5. [梅森旋轉演算法（MT19937）引擎](#5-梅森旋轉演算法mt19937引擎)
6. [金鑰與 IV 產生](#6-金鑰與-iv-產生)
7. [AES 加密](#7-aes-加密)
8. [解密流程](#8-解密流程)
9. [加密流程](#9-加密流程)
10. [實際範例](#10-實際範例)
11. [PowerShell 參考實作](#11-powershell-參考實作)
12. [常數速查表](#12-常數速查表)

---

## 1. 背景

Windows 11 開始功能表主機程序（`StartMenuExperienceHost.exe`）載入 `StartMenu.dll`，
將釘選磚塊、最近啟動的應用程式及其他 UI 狀態序列化為單一二進位檔案 `start2.bin`。

DLL 內負責此工作的命名空間是 `SlimObfuscationManager`，輔助類別為 `StableCryptoFunctions`。磁碟格式如下：

```
     ┌────────────────────────────┐
0x00 │ MAGIC（16 B）             │
0x10 │ HEADER_CONST（16 B）      │
0x20 │ FILETIME（8 B）           │
0x28 │ 總酬載長度（4 B）         │
0x2C │ 前置填充（N B）           │
     ├────────────────────────────┤
     │ AES-256-CBC 密文           │
     ├────────────────────────────┤
     │ 後置填充（512−N B）        │
     └────────────────────────────┘

     N = pad_mt() & 0x1FF（0..511）
     密文長度 = total_payload_length − 0x200
     前置 + 後置填充合計恆為 512 B
```

檔案以 **AES-256-CBC + PKCS#7 填充** 加密。256 位元金鑰與 128 位元 IV 由兩個獨立的 **MT19937** 偽隨機數產生器衍生，各自以檔案本身的 `FILETIME` 欄位結合兩個嵌入常數作為種子。

由於種子材料以明文儲存於檔案標頭，任何讀取者均可確定性地重建金鑰；因此本構造應稱為**混淆**，而非帶驗證的加密。

---

## 2. 磁碟路徑

```
%LocalAppData%\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\
    start2.bin
```

每當使用者釘選、取消釘選或重新排列磚塊時，開始功能表主機會以原子寫入方式更新這個檔案。

---

## 3. 檔案佈局

所有多位元組整數欄位均為 **little-endian**。

| 偏移量   | 大小        | 欄位                      | 說明                                                     |
|---------:|------------:|---------------------------|----------------------------------------------------------|
| `0x00`   | 16 B        | `MAGIC`                   | 固定 GUID，以 WinRT `WriteGuid` 位元組順序序列化         |
| `0x10`   | 16 B        | `HEADER_CONST`            | 固定 16 位元組常數，逐字寫入                             |
| `0x20`   | 4 B         | `FILETIME.dwLowDateTime`  | `GetSystemTimeAsFileTime()` 的低 32 位元                 |
| `0x24`   | 4 B         | `FILETIME.dwHighDateTime` | `GetSystemTimeAsFileTime()` 的高 32 位元                 |
| `0x28`   | 4 B         | `total_payload_length`    | `ciphertext_len + 0x200`                                 |
| `0x2C`   | `N` B       | 前置填充                  | 隨機位元組，`N = pad_mt() & 0x1FF`（0..511）             |
| `0x2C+N` | `M` B       | 密文                      | `M = total_payload_length − 0x200`                       |
| `0x2C+N+M` | `0x200−N` B | 後置填充              | 隨機位元組，前置 + 後置合計恆為 512                      |

### 3.1 `MAGIC` 位元組表示方式

DLL 映像中，GUID 以標準 `GUID` 結構儲存
（`{E27AE14B-01FC-4D1B-8551-6EDE0B81009C}`），即記憶體中為：

```
4B E1 7A E2  FC 01  1B 4D  85 51  6E DE 0B 81 00 9C
└── Data1 ──┘ Data2 Data3 └─────── Data4 ────────┘
```

執行期透過 `IDataWriter::WriteGuid` 寫入，該函式將 `Data1`/`Data2`/`Data3` 各元件以 **big-endian** 序列化：

```
磁碟上：  E2 7A E1 4B  01 FC  4D 1B  85 51 6E DE 0B 81 00 9C
                                     └────── Data4 原始 ──────┘
```

程式驗證 MAGIC 時應比對下方的**磁碟位元組序列**，而非 GUID 結構：

```
E2 7A E1 4B 01 FC 4D 1B 9C 00 81 0B DE 6E 51 85
```

### 3.2 `HEADER_CONST`

MAGIC 之後緊跟第二個固定常數。它在堆疊上以四個 little-endian DWORD 初始化，並由 `IDataWriter::WriteBytes` 寫入，因此磁碟位元組與記憶體位元組完全一致：

```
DWORD[0] = 0x475F5A4E   →  4E 5A 5F 47
DWORD[1] = 0x49B15B00   →  00 5B B1 49
DWORD[2] = 0xAF925C8A   →  8A 5C 92 AF
DWORD[3] = 0x5EF98490   →  90 84 F9 5E

磁碟上：  4E 5A 5F 47 00 5B B1 49 8A 5C 92 AF 90 84 F9 5E
```

此常數無已知語意，視為不透明魔術數字即可。

### 3.3 填充計算

前置 + 後置填充合計恆為 **0x200（512）** 位元組——兩者共享固定配額，並非各自獨立占用 512 位元組。切割點 `N = pad_mt() & 0x1FF` 決定前置填充的長度（0..511 位元組），剩餘的 `0x200 − N`（1..512 位元組）即為後置填充。每個檔案只有切割點不同，因此檔案大小恆為：

```
file_size = 0x2C + 0x200 + ciphertext_len
          = total_payload_length + 0x2C
```

---

## 4. 密碼學常數

加密提供者中嵌入兩個 32 位元常數：

| 名稱           | 值            | 用途                                              |
|----------------|---------------|---------------------------------------------------|
| `PROV_KEY_DW0` | `0x3B21D91E`  | XOR 進金鑰/IV 的 MT 種子                          |
| `PROV_KEY_DW1` | `0x4D9700AF`  | 填充 MT 種子常數的來源                            |
| `PROV_KEY_DW2` | `0x8E2AB4AA`  | 已分配但不在密碼學路徑上使用                      |
| `PROV_KEY_DW3` | `0xEAA91EA8`  | 已分配但不在密碼學路徑上使用                      |

每次加解密計算一次衍生常數：

```
PAD_SEED_CONST = ((PROV_KEY_DW1 & 0xFFFF) << 16)
               |  (PROV_KEY_DW1 >> 16)
               =  0x00AF4D97
```

等價說明：將 `PROV_KEY_DW1` 的高低 16 位元半字對換。

---

## 5. 梅森旋轉演算法（MT19937）引擎

本格式使用**標準 32 位元梅森旋轉演算法**（與 C++ `std::mt19937` 相同）。所有範本參數均已由二進位驗證：

| 參數                 | 值            |
|----------------------|---------------|
| 字組大小             | 32            |
| 狀態大小（N）        | 624           |
| 移位大小（M）        | 397           |
| 遮罩位元             | 31            |
| `MATRIX_A`           | `0x9908B0DF`  |
| 調製參數 `u`         | 11            |
| 調製參數 `d`         | `0xFFFFFFFF`  |
| 調製參數 `s`         | 7             |
| 調製參數 `b`         | `0x9D2C5680`  |
| 調製參數 `t`         | 15            |
| 調製參數 `c`         | `0xEFC60000`  |
| 調製參數 `l`         | 18            |
| 初始乘數 `f`         | `0x6C078965`  |

### 5.1 播種

標準 C++11 播種方式：

```c
state[0] = seed;
for (i = 1; i < 624; i++)
    state[i] = (state[i-1] ^ (state[i-1] >> 30)) * 0x6C078965 + i;
```

### 5.2 輸出（`operator()`）

標準調製（tempering）——詳見任何 C++ 參考實作。上方常數已足以逐位元還原。

---

## 6. 金鑰與 IV 產生

### 6.1 兩個獨立的 MT 實例

每個檔案使用兩條 MT19937 串流，均以檔案本身的 `FILETIME` 播種：

```
pad_seed = PAD_SEED_CONST  ^  FILETIME.dwLowDateTime
         = 0x00AF4D97      ^  ft_low

sym_seed = FILETIME.dwHighDateTime  ^  FILETIME.dwLowDateTime  ^  PROV_KEY_DW0
         = ft_high                  ^  ft_low                   ^  0x3B21D91E
```

`pad_mt = MT19937(pad_seed)` 用於：
1. **第一個輸出** 與 `0x1FF` 做 AND 得到 `pre_pad_len`（0..511）。
2. 後續輸出（各截取為一個位元組）填入前置/後置填充。

`sym_mt = MT19937(sym_seed)` 由下方的 `GetSymmetricKeys` 消耗。

### 6.2 `GetSymmetricKeys(sym_seed)`

此常式的常數為：`MIN = 0x40 (64)`、`MAX = 0x80 (128)`、`IV_LEN = 0x10 (16)`。

```
mt        = MT19937(sym_seed)
key_seed  = mt()                                  // 第 1 個輸出
key_len   = MIN + uniform_uint(mt, MAX - MIN)      // 第 2 個輸出（拒絕取樣）
iv_seed   = mt()                                  // 第 3 個輸出

key_str   = AlphaNumericKeyGenerator(key_seed, key_len)   // 64..128 字元
iv_str    = AlphaNumericKeyGenerator(iv_seed,  IV_LEN)    // 16 字元
```

### 6.3 `uniform_uint(mt, range_size)` — 拒絕取樣

對應 C++ `std::uniform_int_distribution<unsigned>`（libc++/MSVC 實作）：

```c
if (range_size == 0)            return 0;
if (range_size == 0xFFFFFFFF)   return mt();

bound = range_size + 1;
while (true) {
    v = mt();
    // 若 v 不落在截斷尾部則接受
    if (!((0xFFFFFFFF / bound) <= (v / bound)
       && (0xFFFFFFFF % bound) != range_size))
        return v % bound;
}
```

對於 `range_size = 0x40`，拒絕率約為 `1.56%`，平均略超過一次 `mt()` 呼叫。

### 6.4 `AlphaNumericKeyGenerator(seed, length)`

以 `seed` 建立第二個 MT，經由隨機偏移量暖機後，輸出可印字元：

```c
mt = MT19937(seed)

// 第一階段：暖機 — 丟棄不定數量的輸出
do {
    v = mt();
} while ((v / 0x3E9) > 0x417873);     // 0x3E9 = 1001
mt.discard(v % 0x3E9);                  // 丟棄 0..1000 個輸出

// 第二階段：產生 length 個可印字元，範圍 [0x20, 0x7F]
for (i = 0; i < length; i++) {
    do {
        v = mt();
    } while ((v / 0x60) > 0x2AAAAA9);  // 0x60 = 96
    out[i] = (uint16_t)((v % 0x60) + 0x20);
}
```

兩個拒絕迴圈在絕大多數情況下第一次即接受（拒絕率分別約 `1.6%` 與 `0.16%`）。

緩衝區 `out` 是 `wchar_t`（UTF-16）字串，但每個字元均在 `[0x20, 0x7F]`（可印 ASCII，含 `0x7F`/DEL）。

### 6.5 字串 → 位元組緩衝區

wchar_t 金鑰/IV 字串傳入
`Windows.Security.Cryptography.CryptographicBuffer.ConvertStringToBinary`，
編碼參數為 `BinaryStringEncoding = 0`（**Utf8**）。

由於所有字元均為純 ASCII，UTF-8 編碼產生**每字元一個位元組**，數值與字元碼相同。最終結果：

* `key_buf` 長 `key_len` 位元組，各位元組在 `[0x20, 0x7F]`，長度在 64..128 之間。
* `iv_buf` 恰好 16 位元組，各位元組在 `[0x20, 0x7F]`。

---

## 7. AES 加密

* 傳入 `SymmetricKeyAlgorithmProvider::OpenAlgorithm` 的演算法字串：**`"AES_CBC_PKCS7"`**。
* `CreateSymmetricKey` 以完整的 `key_buf`（64..128 位元組）呼叫。
  Windows CNG（底層為 BCrypt）選取**可容納的最大 AES 金鑰長度**，即 **AES-256**，並靜默地只使用緩衝區的**前 32 位元組**，其餘忽略。
* IV 為完整的 16 位元組 `iv_buf`。
* PKCS#7 填充自動處理。

換言之，此方案等價於：

```
ciphertext = AES_256_CBC_PKCS7_Encrypt(plaintext, key_buf[:32], iv_buf)
```

此行為已由實驗驗證：以 `key_buf[:16]`（AES-128）解密真實檔案會產生 PKCS#7 填充錯誤；以 `key_buf[:32]`（AES-256）則可正確解密為 JSON 文件。

---

## 8. 解密流程

給定一個 `start2.bin`：

```
 1. 讀取前 16 位元組；驗證是否等於 MAGIC（磁碟位元組形式，§3.1）。
 2. 讀取 [0x10:0x20]；驗證是否等於 HEADER_CONST。
 3. ft_low  = u32_le @ 0x20 ；ft_high = u32_le @ 0x24
 4. total_len = u32_le @ 0x28
 5. ciphertext_len = total_len − 0x200   ；必須 ≥ 0 且為 16 的倍數

 6. pad_seed   = 0x00AF4D97 ^ ft_low
    pad_mt     = MT19937(pad_seed)
    pre_pad    = pad_mt() & 0x1FF         ；僅使用第一個輸出
    cipher_off = 0x2C + pre_pad
    ciphertext = data[cipher_off : cipher_off + ciphertext_len]

 7. sym_seed   = ft_high ^ ft_low ^ 0x3B21D91E
    (key_buf, iv_buf) = GetSymmetricKeys(sym_seed)

 8. plaintext = AES_256_CBC_PKCS7_Decrypt(ciphertext, key_buf[:32], iv_buf)
```

明文為描述使用者釘選磚塊狀態的 UTF-8 JSON 文件（`{ ... }`）。

---

## 9. 加密流程

從 JSON 明文產生 `start2.bin`：

```
 1. ft = GetSystemTimeAsFileTime()           ；或任何 64 位元值
 2. pad_seed = 0x00AF4D97 ^ ft.low
    pad_mt    = MT19937(pad_seed)
    pre_pad   = pad_mt() & 0x1FF
    post_pad  = 0x200 − pre_pad
 3. sym_seed = ft.high ^ ft.low ^ 0x3B21D91E
    (key_buf, iv_buf) = GetSymmetricKeys(sym_seed)
 4. ciphertext = AES_256_CBC_PKCS7_Encrypt(plaintext, key_buf[:32], iv_buf)
 5. total_len = len(ciphertext) + 0x200

 6. 依序輸出：
      MAGIC              （16 位元組，磁碟位元組形式）
      HEADER_CONST       （16 位元組）
      ft.low             （4 位元組，LE）
      ft.high            （4 位元組，LE）
      total_len          （4 位元組，LE）
      pre_pad 個位元組   ← 取自 pad_mt() & 0xFF
      ciphertext         （total_len − 0x200 位元組）
      post_pad 個位元組  ← 取自 pad_mt() & 0xFF
```

填充位元組以相同的 MT 實例後續輸出截取為一個位元組逐一產生。讀取時不驗證其數值，因此任何隨機來源均可接受；原始實作直接延續同一個 MT 實例。

---

## 10. 實際範例

一個真實的 `start2.bin` 檔案標頭位元組如下：

```
0x00:  E2 7A E1 4B 01 FC 4D 1B 9C 00 81 0B DE 6E 51 85   ; MAGIC      ✓
0x10:  4E 5A 5F 47 00 5B B1 49 8A 5C 92 AF 90 84 F9 5E   ; HEADER     ✓
0x20:  17 D5 1D BC EF D4 DC 01                            ; FILETIME
0x28:  90 3D 00 00                                        ; total_len = 0x3D90 = 15760
```

衍生計算：

```
ft_low      = 0xBC1DD517
ft_high     = 0x01DCD4EF

pad_seed    = 0x00AF4D97 ^ 0xBC1DD517 = 0xBCB29880
pad_mt      = MT19937(0xBCB29880)
pre_pad     = pad_mt() & 0x1FF = 294（十進位）
post_pad    = 512 − 294 = 218

ciphertext_len = 0x3D90 − 0x200 = 0x3B90 = 15248
cipher_off     = 0x2C + 294 = 0x152

sym_seed    = 0x01DCD4EF ^ 0xBC1DD517 ^ 0x3B21D91E = 0x86E0D8E6
(key_buf, iv_buf) = GetSymmetricKeys(0x86E0D8E6)
              → key_buf = b"FplVt'UjdEX\\hi\\oK'(+~c5$i%T++xZ&=GT~28..."   (105 位元組)
              → iv_buf  = b'_9AFrlIN9CCr"Ynn'                              (16 位元組)

plaintext   = AES_256_CBC_PKCS7_Decrypt(
                ciphertext = data[0x152 : 0x152 + 15248],
                key        = key_buf[:32],
                iv         = iv_buf,
              )
            → b'{ "...": ... }'    (UTF-8 JSON)
```

本例中 `key_len` 恰好為 105；其他檔案的值會落在 `[64, 128]` 之間，由第二個 MT 輸出決定。

---

## 11. PowerShell 參考實作

以下完整 PowerShell 腳本可讀取任何 `start2.bin` 並印出明文 JSON。
僅需 PowerShell 5.1+（Windows 內建），無任何外部依賴。

```powershell
#!/usr/bin/env pwsh
<#
.SYNOPSIS
解密 Windows 11 開始功能表 start2.bin 檔案。
#>
#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- MT19937（對應 std::mt19937 / C++11 mersenne_twister_engine<uint32_t,...>）---
class MT19937 {
    [uint32[]]$State
    [int]$Index

    MT19937([uint32]$seed) {
        $this.State = New-Object 'uint32[]' 624
        $this.State[0] = $seed
        for ($i = 1; $i -lt 624; $i++) {
            [long]$prev = $this.State[$i - 1]
            [long]$x = $prev -bxor ($prev -shr 30)
            $x = ($x * 0x6C078965L + $i) -band 0xFFFFFFFFL
            $this.State[$i] = [uint32]$x
        }
        $this.Index = 624
    }

    [void]Refresh() {
        for ($i = 0; $i -lt 624; $i++) {
            [long]$y = ([long]$this.State[$i] -band 0x80000000L) -bor `
                       ([long]$this.State[($i + 1) % 624] -band 0x7FFFFFFFL)
            [long]$val = [long]$this.State[($i + 397) % 624] -bxor ($y -shr 1)
            if ($y -band 1L) { $val = $val -bxor 0x9908B0DFL }
            $this.State[$i] = [uint32]($val -band 0xFFFFFFFFL)
        }
        $this.Index = 0
    }

    [uint32]Next() {
        if ($this.Index -ge 624) { $this.Refresh() }
        [long]$y = [long]$this.State[$this.Index]
        $this.Index++
        $y = ($y -bxor ($y -shr 11)) -band 0xFFFFFFFFL
        $y = ($y -bxor (($y -shl 7)  -band 0x9D2C5680L)) -band 0xFFFFFFFFL
        $y = ($y -bxor (($y -shl 15) -band 0xEFC60000L)) -band 0xFFFFFFFFL
        $y = ($y -bxor ($y -shr 18)) -band 0xFFFFFFFFL
        return [uint32]$y
    }

    [void]Discard([int]$n) {
        for ($i = 0; $i -lt $n; $i++) { [void]$this.Next() }
    }
}

# --- uniform_int_distribution<unsigned int>（拒絕取樣）---
function Get-UniformUint {
    param([MT19937]$Mt, [uint32]$RangeSize)

    if ($RangeSize -eq 0) { return [uint32]0 }
    if ($RangeSize -eq 0xFFFFFFFFL) { return $Mt.Next() }

    [long]$bound = [long]$RangeSize + 1L
    while ($true) {
        [long]$v   = [long]$Mt.Next()
        [long]$rem = $v % $bound
        $condA = ([long]0xFFFFFFFFL / $bound) -le ($v / $bound)
        $condB = ([long]0xFFFFFFFFL % $bound) -ne $RangeSize
        if (-not ($condA -and $condB)) { return [uint32]$rem }
    }
}

# --- AlphaNumericKeyGenerator(seed, length) -> byte[] ---
function Get-AlphaNumericKey {
    param([uint32]$Seed, [int]$Length)

    $mt = [MT19937]::new($Seed)

    # 第一階段：暖機 — 丟棄不定數量的輸出
    while ($true) {
        [long]$v = [long]$mt.Next()
        if ([long]([math]::Floor($v / 0x3E9L)) -le 0x417873L) { break }
    }
    $mt.Discard([int]($v % 0x3E9L))

    # 第二階段：產生 length 個位元組，範圍 [0x20, 0x80)
    $out = New-Object 'byte[]' $Length
    for ($i = 0; $i -lt $Length; $i++) {
        while ($true) {
            [long]$w = [long]$mt.Next()
            if ([long]([math]::Floor($w / 0x60L)) -le 0x2AAAAA9L) { break }
        }
        $out[$i] = [byte](($w % 0x60L) + 0x20L)
    }
    return $out
}

# --- GetSymmetricKeys(sym_seed) -> (key_buf, iv_buf) ---
function Get-SymmetricKeys {
    param([uint32]$SymSeed)

    $MIN_KEY = 0x40
    $MAX_KEY = 0x80
    $IV_LEN  = 0x10

    $mt       = [MT19937]::new($SymSeed)
    $keySeed  = $mt.Next()
    $keyLen   = $MIN_KEY + (Get-UniformUint -Mt $mt -RangeSize ([uint32]($MAX_KEY - $MIN_KEY)))
    $ivSeed   = $mt.Next()

    $keyBytes = Get-AlphaNumericKey -Seed $keySeed -Length $keyLen
    $ivBytes  = Get-AlphaNumericKey -Seed $ivSeed  -Length $IV_LEN

    # WinRT 僅使用前 32 位元組作為 AES-256 金鑰
    $keyTrunc = New-Object 'byte[]' 32
    [Array]::Copy($keyBytes, 0, $keyTrunc, 0, 32)

    return @{ Key = $keyTrunc; Iv = $ivBytes }
}

$MAGIC        = [byte[]](0xE2,0x7A,0xE1,0x4B, 0x01,0xFC, 0x4D,0x1B, 0x9C,0x00, 0x81,0x0B,0xDE,0x6E,0x51,0x85)
$HEADER_CONST = [byte[]](0x4E,0x5A,0x5F,0x47, 0x00,0x5B, 0xB1,0x49, 0x8A,0x5C, 0x92,0xAF,0x90,0x84,0xF9,0x5E)

function Decrypt-Start2Bin {
    param([string]$Path)

    $data = [System.IO.File]::ReadAllBytes($Path)

    # 驗證標頭
    for ($i = 0; $i -lt 16; $i++) {
        if ($data[$i] -ne $MAGIC[$i]) { throw "MAGIC 不符" }
    }
    for ($i = 0; $i -lt 16; $i++) {
        if ($data[16 + $i] -ne $HEADER_CONST[$i]) { throw "HEADER_CONST 不符" }
    }

    $ftLow  = [BitConverter]::ToUInt32($data, 0x20)
    $ftHigh = [BitConverter]::ToUInt32($data, 0x24)
    $totLen = [BitConverter]::ToUInt32($data, 0x28)
    $cipherLen = [int]($totLen - 0x200)

    $PAD_SEED_CONST = 0x00AF4D97L
    $padSeed = [uint32]((($PAD_SEED_CONST) -bxor [long]$ftLow) -band 0xFFFFFFFFL)
    $padMt   = [MT19937]::new($padSeed)
    $prePad  = [int]($padMt.Next() -band 0x1FF)
    $cipherOff = 0x2C + $prePad

    $ciphertext = New-Object 'byte[]' $cipherLen
    [Array]::Copy($data, $cipherOff, $ciphertext, 0, $cipherLen)

    $PROV_KEY_DW0 = 0x3B21D91EL
    $symSeed = [uint32]((([long]$ftHigh) -bxor ([long]$ftLow) -bxor $PROV_KEY_DW0) -band 0xFFFFFFFFL)
    $keys = Get-SymmetricKeys -SymSeed $symSeed

    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key     = $keys.Key
        $aes.IV      = $keys.Iv
        $decryptor = $aes.CreateDecryptor()
        try {
            return $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
        } finally { $decryptor.Dispose() }
    } finally { $aes.Dispose() }
}

if ($args.Count -ne 1) {
    Write-Error "用法：.\decrypt_start2.ps1 <start2.bin 路徑>"
    exit 1
}
$plain = Decrypt-Start2Bin -Path $args[0]
[System.Text.Encoding]::UTF8.GetString($plain)
```

此腳本假設輸入檔案格式正確，否則立即失敗。正式使用時，請將 `throw` 改為明確的錯誤處理，並對 `total_len`、`cipher_len`、`pre_pad` 加入防禦性檢查。

---

## 12. 常數速查表

| 名稱                          | 值                                                       |
|-------------------------------|----------------------------------------------------------|
| `MAGIC`（磁碟上）             | `E2 7A E1 4B 01 FC 4D 1B 9C 00 81 0B DE 6E 51 85`        |
| `MAGIC`（DLL 中的 GUID 結構） | `4B E1 7A E2 FC 01 1B 4D 85 51 6E DE 0B 81 00 9C`        |
| `MAGIC`（標準形式）           | `{E27AE14B-01FC-4D1B-8551-6EDE0B81009C}`                 |
| `HEADER_CONST`                | `4E 5A 5F 47 00 5B B1 49 8A 5C 92 AF 90 84 F9 5E`        |
| `PROV_KEY_DW0`                | `0x3B21D91E`                                             |
| `PROV_KEY_DW1`                | `0x4D9700AF`                                             |
| `PROV_KEY_DW2`（未使用）      | `0x8E2AB4AA`                                             |
| `PROV_KEY_DW3`（未使用）      | `0xEAA91EA8`                                             |
| `PAD_SEED_CONST`              | `0x00AF4D97`                                             |
| `MIN_KEY_LEN`                 | `0x40`（64 字元 / UTF-8 編碼後 64 位元組）               |
| `MAX_KEY_LEN`                 | `0x80`（128 字元 / UTF-8 編碼後 128 位元組）             |
| `AES_KEY_LEN`                 | `0x20`（32 位元組 — AES-256，取自 `key_buf[:32]`）       |
| `AES_BLOCK_SIZE`              | `0x10`（16 位元組 — IV 長度與 CBC 區塊大小）             |
| `PAYLOAD_PAD_TOTAL`           | `0x200`（512 — 每個檔案的前置 + 後置填充位元組數）       |
| 演算法字串                    | `"AES_CBC_PKCS7"`                                        |
| AlphaNumeric 字元範圍         | `[0x20, 0x7F]`（96 種可印 ASCII 值）                     |
| 第一階段拒絕條件              | `v / 0x3E9 > 0x417873`                                   |
| 第二階段拒絕條件              | `v / 0x60  > 0x2AAAAA9`                                  |
| MT19937 初始乘數 `f`          | `0x6C078965`                                             |
| MT19937 `MATRIX_A`            | `0x9908B0DF`                                             |

---

### 規格結尾

以上內容已足以逐位元組地讀取、驗證及寫入 `start2.bin` 檔案，無需任何其他參考資料。
密碼學路徑中沒有隱藏步驟、驗證標籤或版本相依的分支：
所有已檢視的 Windows 組建均使用相同的演算法。
