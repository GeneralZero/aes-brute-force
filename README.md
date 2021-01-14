# aes-brute-force
Using Hardware AES instructions (on both Intel and ARM) with c++ threads to search AES keys. This suppports 128, 192 and 256 AES keys.
Sometimes side channel attacks recover most key bytes but not all. This project allows to brute force remaining bytes on commodity hardware. 

The AES-NI code has been taken from [Botan](https://github.com/randombit/botan) with some modifications.

### Installing and Compiling

```bash
git clone https://github.com/GeneralZero/aes-brute-force/
make
./aes-brute-force-fast
#AES encryption key brute force search
#Usage 1: ./aes-brute-force-fast <key_mask> <key_in> <plain> <cipher> [byte_min] [byte_max] [n_threads]
#Usage 2: ./aes-brute-force-fast <key_mask> <key_in> <plain> <cipher> restrict <sorted list of bytes> [n_threads]
```

## Preformance

### Running on AWS x84-64 (c5ad.8xlarge)

**Command Output:**
```
>>> ./aes-brute-force-fast FF000000_FFFFFFFF_00000000_00000000_00000000_00000000_00000000_00000000 5403e7dbcf2f5909be97b6fe33bfdcc82d95eb862e8fefda14f180d9a407c745 3d7a76d4cca6bd3d8a8d4561722e6025 44949e8716726f928eb111bb899c506e
[...]
        1099511627611 AES128 operations done in 2604.35s
        2ns per AES128 operation
        422.18 million keys per second
```

**Average time to Brute Keys:**
- 4 bytes (32 bits) takes about 5.1 seconds
- 5 bytes (40 bits) takes about 21.5 mins.
- 6 bytes (48 bits) takes about 92.6 hours.

### Running on AWS ARM64 (c6gd.8xlarge)

**Command Output:**
```
>>> ./aes-brute-force-fast FF000000_FFFFFFFF_00000000_00000000_00000000_00000000_00000000_00000000 5403e7dbcf2f5909be97b6fe33bfdcc82d95eb862e8fefda14f180d9a407c745 3d7a76d4cca6bd3d8a8d4561722e6025 44949e8716726f928eb111bb899c506e
[...]
        364383123732 AES128 operations done in 1051.07s
        2ns per AES128 operation
        346.68 million keys per second
```

**Average time to Brute Keys:**
- 4 bytes (32 bits) takes about 6.2 seconds
- 5 bytes (40 bits) takes about 26.4 mins.
- 6 bytes (48 bits) takes about 112.8 Hours.

## Examples

### Bruteforcing Base64 Character set

Arguments do not need to have Underscores but does makes it more readable.

```bash
# base64 Bruteforce
./aes-brute-force-fast FF0000FF_00FF0000_FF00FF00_00000000 0077330053005953004d00775a514778 54455354494e47535452494e47313233 2a3037f7b424d75cfbc97ad5626fa479 restrict 2B2F303132333435363738393D4142434445464748494A4B4C4D4E4F505152535455565758595A6162636465666768696A6B6C6D6E6F707172737475767778797A
```

### Bruteforcing Hex Character set

```bash
# Hex Uppercase bruteforce
./aes-brute-force-fast FFFFFFFF_FF00FFFF_0000FF00_00000000 007E1500_2800D2A6_ABF70088_09CF4F3C 3243F6A8_885A308D_313198A2_E0370734 3925841D_02DC09FB_DC118597_196A0B32 restrict 30_31_32_33_34_35_36_37_38_39_41_42_43_44_45_46

# Hex Lowercase bruteforce
./aes-brute-force-fast FF000000_FF00FF00_0000FF00_FF00FF00 00333038003300376438003500660064 54455354494e47535452494e47313233 f11aa12cf33991b95d5ccc73dd0e0024 restrict 30_31_32_33_34_35_36_37_38_39_61_62_63_64_65_66

# Hex mixedcase bruteforce
./aes-brute-force-fast FF0000FF_FF00FFFF_0000FF00_00000000 007E1500_2800D2A6_ABF70088_09CF4F3C 3243F6A8_885A308D_313198A2_E0370734 3925841D_02DC09FB_DC118597_196A0B32 restrict 30_31_32_33_34_35_36_37_38_39_41_42_43_44_45_46_61_62_63_64_65_66
````

### Bruteforcing Printable Character set

```bash
# Brute forcing all of the printable Character set
./aes-brute-force-fast FF000000_FF00FF00_FF000000_FF000000 2b25596240264a464c29745c51546174 54455354494e47535452494e47313233 da9a6a55e3368dd89c46920b9c6ecd79 restrict 303132333435363738396162636465666768696a6b6c6d6e6f707172737475767778797a4142434445464748494a4b4c4d4e4f505152535455565758595a2122232425262728292a2b2c2d2e2f3a3b3c3d3e3f405b5c5d5e5f607b7c7d7e20090a0d0b0c

```

### Bruteforcing UTF-16LE Character set

```bash
# Combination of hex_lowercase and UTF-16LE
./aes-brute-force-fast FF00FF00_FF00FF00_FF00FF00_FF00FF00 007E1500_2800D2A6_ABF70088_09CF4F3C 3243F6A8_885A308D_313198A2_E0370734 3925841D_02DC09FB_DC118597_196A0B32 restrict 30_31_32_33_34_35_36_37_38_39_61_62_63_64_65_66
```

### Thanks

Thanks to [sebastien-riou/aes-brute-force](https://github.com/sebastien-riou/aes-brute-force) and [Botan](https://github.com/randombit/botan) open source projects that I used for the insperation, sanity checking and code.
