#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================ Constants

$Script:DefaultStart2Path = Join-Path $env:LOCALAPPDATA `
    'Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\start2.bin'

$Script:MAGIC_GUID = [byte[]](
    0xE2,0x7A,0xE1,0x4B, 0x01,0xFC, 0x4D,0x1B,
    0x9C,0x00, 0x81,0x0B,0xDE,0x6E,0x51,0x85)

$Script:HEADER_CONST = [byte[]](
    0x4E,0x5A,0x5F,0x47, 0x00,0x5B, 0xB1,0x49,
    0x8A,0x5C, 0x92,0xAF,0x90,0x84,0xF9,0x5E)

$Script:PROV_KEY_DW0   = 0x3B21D91EL
$Script:PAD_SEED_CONST = 0x00AF4D97L
$Script:MIN_KEY_LEN    = 0x40
$Script:MAX_KEY_LEN    = 0x80
$Script:IV_LEN         = 0x10
$Script:PAD_TOTAL      = 0x200
$Script:CloudStoreCacheRoot = `
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount'

# ============================================================ MT19937
# MSVC std::mt19937 — exact match (matches decrypt_start2.py).

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

# ============================================================ Distribution / KDF

function Script:Get-UniformUint32 {
    param(
        [Parameter(Mandatory)] [MT19937]$Mt,
        [Parameter(Mandatory)] [uint32]$Range   # range_size = max - min
    )
    if ($Range -eq 0) { return [uint32]0 }
    if ($Range -eq 0xFFFFFFFFL) { return $Mt.Next() }
    [long]$bound = [long]$Range + 1L
    while ($true) {
        [long]$v   = [long]$Mt.Next()
        [long]$rem = $v % $bound
        $condA = ([long]0xFFFFFFFFL / $bound) -le ($v / $bound)
        $condB = ([long]0xFFFFFFFFL % $bound) -ne $Range
        if (-not ($condA -and $condB)) { return [uint32]$rem }
    }
    return [uint32]0   # unreachable; placates parser
}

function Script:Get-AlphaNumericKey {
    param(
        [Parameter(Mandatory)] [uint32]$Seed,
        [Parameter(Mandatory)] [int]$Length
    )
    $mt = [MT19937]::new($Seed)

    # Phase 1: discard pass
    while ($true) {
        [long]$v = [long]$mt.Next()
        if ([long]([math]::Floor($v / 0x3E9L)) -le 0x417873L) { break }
    }
    $mt.Discard([int]($v % 0x3E9L))

    # Phase 2: emit `Length` bytes in [0x20, 0x80)
    $out = New-Object 'byte[]' $Length
    for ($i = 0; $i -lt $Length; $i++) {
        while ($true) {
            [long]$w = [long]$mt.Next()
            if ([long]([math]::Floor($w / 0x60L)) -le 0x2AAAAA9L) { break }
        }
        $out[$i] = [byte](($w % 0x60L) + 0x20L)
    }
    return ,$out
}

function Script:Get-SymmetricKey {
    param([Parameter(Mandatory)] [uint32]$SymSeed)

    $mt        = [MT19937]::new($SymSeed)
    $keySeed   = $mt.Next()
    $randOff   = Get-UniformUint32 -Mt $mt -Range ([uint32]($Script:MAX_KEY_LEN - $Script:MIN_KEY_LEN))
    $ivSeed    = $mt.Next()

    $keyLen    = [int]$randOff + $Script:MIN_KEY_LEN
    $keyBytes  = Get-AlphaNumericKey -Seed $keySeed -Length $keyLen
    $ivBytes   = Get-AlphaNumericKey -Seed $ivSeed  -Length $Script:IV_LEN

    # WinRT picks the largest AES variant supported, so the first 32 bytes are
    # used as an AES-256 key. (key_str is 64-128 bytes, IV is always 16.)
    $keyTrunc = New-Object 'byte[]' 32
    [Array]::Copy($keyBytes, 0, $keyTrunc, 0, 32)

    return [pscustomobject]@{
        Key    = $keyTrunc
        FullKey = $keyBytes
        Iv     = $ivBytes
        KeyLen = $keyLen
    }
}

# ============================================================ AES-CBC-PKCS7

function Script:Invoke-AesCbcPkcs7 {
    param(
        [Parameter(Mandatory)] [byte[]]$Data,
        [Parameter(Mandatory)] [byte[]]$Key,
        [Parameter(Mandatory)] [byte[]]$InitVector,
        [Parameter(Mandatory)] [ValidateSet('Encrypt','Decrypt')] [string]$Mode
    )
    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key     = $Key
        $aes.IV      = $InitVector
        if ($Mode -eq 'Encrypt') {
            $xform = $aes.CreateEncryptor()
        } else {
            $xform = $aes.CreateDecryptor()
        }
        try {
            return ,$xform.TransformFinalBlock($Data, 0, $Data.Length)
        } finally { $xform.Dispose() }
    } finally { $aes.Dispose() }
}

# ============================================================ Frame parser / builder

function Script:ConvertFrom-Start2Frame {
    param([Parameter(Mandatory)] [byte[]]$Bytes)

    if ($Bytes.Length -lt 0x2C) { throw "file too short ($($Bytes.Length) bytes)" }

    for ($i = 0; $i -lt 16; $i++) {
        if ($Bytes[$i] -ne $Script:MAGIC_GUID[$i]) {
            $hex = ($Bytes[0..15] | ForEach-Object { '{0:x2}' -f $_ }) -join ''
            throw "bad magic GUID: $hex"
        }
    }
    for ($i = 0; $i -lt 16; $i++) {
        if ($Bytes[16 + $i] -ne $Script:HEADER_CONST[$i]) {
            Write-Warning ("header constant differs at offset 0x{0:x2}" -f (16 + $i))
            break
        }
    }

    $ftLow   = [BitConverter]::ToUInt32($Bytes, 0x20)
    $ftHigh  = [BitConverter]::ToUInt32($Bytes, 0x24)
    $totLen  = [BitConverter]::ToUInt32($Bytes, 0x28)
    if ($totLen -lt $Script:PAD_TOTAL) { throw "bad total_len $totLen" }
    $cipherLen = [int]($totLen - $Script:PAD_TOTAL)

    $padSeed = [uint32]((($Script:PAD_SEED_CONST) -bxor [long]$ftLow) -band 0xFFFFFFFFL)
    $padMt   = [MT19937]::new($padSeed)
    $prePad  = [int]($padMt.Next() -band 0x1FF)
    $postPad = $Script:PAD_TOTAL - $prePad

    $cipherOff = 0x2C + $prePad
    if ($Bytes.Length -lt ($cipherOff + $cipherLen + $postPad)) { throw "file truncated" }

    $ct = New-Object 'byte[]' $cipherLen
    [Array]::Copy($Bytes, $cipherOff, $ct, 0, $cipherLen)

    return [pscustomobject]@{
        FileTimeLow  = $ftLow
        FileTimeHigh = $ftHigh
        PrePadLen    = $prePad
        PostPadLen   = $postPad
        Ciphertext   = $ct
    }
}

# ============================================================ Registry helper

function Script:Get-RoamedTilePropertiesMapKey {
    if (-not (Test-Path -LiteralPath $Script:CloudStoreCacheRoot)) { return $null }
    Get-ChildItem -LiteralPath $Script:CloudStoreCacheRoot -ErrorAction SilentlyContinue |
        Where-Object {
            $_.PSChildName -like '$*windows.data.unifiedtile.roamedtilepropertiesmap'
        } | Select-Object -First 1
}

function Script:Write-RoamedTilePropertiesMap {
    param([Parameter(Mandatory)] [byte[]]$Bytes)
    $key = Get-RoamedTilePropertiesMapKey
    if (-not $key) {
        Write-Warning "RoamedTilePropertiesMap cache key not found; skipping registry backup."
        return
    }
    $current = "$($key.PSPath)\Current"
    if (-not (Test-Path -LiteralPath $current)) {
        Write-Warning "Registry key '$current' missing; skipping registry backup."
        return
    }
    Set-ItemProperty -LiteralPath $current -Name Data -Type Binary -Value $Bytes
}

# ============================================================ Public API

function Unprotect-StartMenuBin {
    <#
    .SYNOPSIS
    Decrypt a Windows 11 start2.bin (or .bak) file and return the plaintext.

    .PARAMETER Path
    Path to the start2.bin file. Defaults to
    %LOCALAPPDATA%\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\start2.bin

    .PARAMETER AsBytes
    Return raw byte[] instead of a UTF-8 decoded string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)] [string]$Path = $Script:DefaultStart2Path,
        [switch]$AsBytes
    )
    if (-not (Test-Path -LiteralPath $Path)) { throw "file not found: $Path" }
    $blob = [System.IO.File]::ReadAllBytes($Path)
    $info = ConvertFrom-Start2Frame -Bytes $blob

    $symSeed = [uint32]((([long]$info.FileTimeHigh) -bxor `
                        ([long]$info.FileTimeLow)  -bxor `
                        $Script:PROV_KEY_DW0) -band 0xFFFFFFFFL)
    $sym = Get-SymmetricKey -SymSeed $symSeed
    $plain = Invoke-AesCbcPkcs7 -Data $info.Ciphertext -Key $sym.Key -InitVector $sym.Iv -Mode Decrypt

    if ($AsBytes) { return ,$plain }
    return [System.Text.Encoding]::UTF8.GetString($plain)
}

function Protect-StartMenuBin {
    <#
    .SYNOPSIS
    Encrypt a string into the start2.bin frame and write it to disk.

    .PARAMETER PlainText
    The plaintext (typically JSON) to encrypt.

    .PARAMETER Path
    Output path. Defaults to the live start2.bin location. When the default
    path is used, the same encrypted blob is also written to the
    RoamedTilePropertiesMap cache key under HKCU.

    .PARAMETER NoRegistryBackup
    When writing to the default path, skip the registry backup write.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [string]$PlainText,

        [Parameter(Position = 1)] [string]$Path,

        [switch]$NoRegistryBackup
    )
    process {
        $useDefault = -not $PSBoundParameters.ContainsKey('Path')
        if ($useDefault) { $Path = $Script:DefaultStart2Path }

        $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)

        [long]$ft       = [DateTime]::UtcNow.ToFileTimeUtc()
        [uint32]$ftLow  = [uint32]($ft -band 0xFFFFFFFFL)
        [uint32]$ftHigh = [uint32](($ft -shr 32) -band 0xFFFFFFFFL)

        $symSeed = [uint32]((([long]$ftHigh) -bxor ([long]$ftLow) -bxor $Script:PROV_KEY_DW0) -band 0xFFFFFFFFL)
        $sym     = Get-SymmetricKey -SymSeed $symSeed
        $ct      = Invoke-AesCbcPkcs7 -Data $plainBytes -Key $sym.Key -InitVector $sym.Iv -Mode Encrypt

        $padSeed = [uint32]((($Script:PAD_SEED_CONST) -bxor [long]$ftLow) -band 0xFFFFFFFFL)
        $padMt   = [MT19937]::new($padSeed)
        $prePad  = [int]($padMt.Next() -band 0x1FF)
        $postPad = $Script:PAD_TOTAL - $prePad
        $totLen  = [uint32]($ct.Length + $Script:PAD_TOTAL)
        $size    = 0x2C + $prePad + $ct.Length + $postPad
        $buf     = New-Object 'byte[]' $size

        [Array]::Copy($Script:MAGIC_GUID,   0, $buf, 0x00, 16)
        [Array]::Copy($Script:HEADER_CONST, 0, $buf, 0x10, 16)
        [Array]::Copy([BitConverter]::GetBytes($ftLow),  0, $buf, 0x20, 4)
        [Array]::Copy([BitConverter]::GetBytes($ftHigh), 0, $buf, 0x24, 4)
        [Array]::Copy([BitConverter]::GetBytes($totLen), 0, $buf, 0x28, 4)

        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try {
            if ($prePad -gt 0) {
                $pre = New-Object 'byte[]' $prePad
                $rng.GetBytes($pre)
                [Array]::Copy($pre, 0, $buf, 0x2C, $prePad)
            }
            [Array]::Copy($ct, 0, $buf, 0x2C + $prePad, $ct.Length)
            if ($postPad -gt 0) {
                $post = New-Object 'byte[]' $postPad
                $rng.GetBytes($post)
                [Array]::Copy($post, 0, $buf, 0x2C + $prePad + $ct.Length, $postPad)
            }
        } finally { $rng.Dispose() }

        $dir = Split-Path -Parent $Path
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        [System.IO.File]::WriteAllBytes($Path, $buf)
        Write-Verbose "wrote $($buf.Length) bytes to $Path"

        if ($useDefault -and -not $NoRegistryBackup) {
            try {
                Write-RoamedTilePropertiesMap -Bytes $buf
                Write-Verbose "registry backup updated"
            } catch {
                Write-Warning "registry backup failed: $($_.Exception.Message)"
            }
        }
    }
}

Export-ModuleMember -Function Unprotect-StartMenuBin, Protect-StartMenuBin
