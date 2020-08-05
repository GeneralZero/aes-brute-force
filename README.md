# aes-brute-force
Using Intel AES-NI and c++ threads to search AES keys. This suppports 128, 192 and 256 AES keys.
Sometimes side channel attacks recover most key bytes but not all. This project allows to brute force remaining bytes on commodity hardware. 

The AES-NI code has been taken from boton with some modifications.

## Measured performances
On a i7-9700K CPU @ 3.60GHz with a 128 bit key.
- 4 bytes (32 bits) takes about 3.4 seconds
- 5 bytes (40 bits) takes about 15 mins.

## Examples

### Bruteforcing Base64 Character set

```bash
# base64 Bruteforce
./aes-brute-force FF00FF00_FF00FF00_FF00FF00_FF00FF00 007E1500_2800D2A6_ABF70088_09CF4F3C 3243F6A8_885A308D_313198A2_E0370734 3925841D_02DC09FB_DC118597_196A0B32 restrict 2B_2F_30_31_32_33_34_35_36_37_38_39_3D_41_42_43_44_45_46_47_48_49_4A_4B_4C_4D_4E_4F_50_51_52_53_54_55_56_57_58_59_5A_61_62_63_64_65_66_67_68_69_6A_6B_6C_6D_6E_6F_70_71_72_73_74_75_76_77_78_79_7A
```

### Bruteforcing Hex Character set

```bash
# hex uppercase bruteforce

./aes-brute-force FF00FF00_FF00FF00_FF00FF00_FF00FF00 007E1500_2800D2A6_ABF70088_09CF4F3C 3243F6A8_885A308D_313198A2_E0370734 3925841D_02DC09FB_DC118597_196A0B32 restrict 30_31_32_33_34_35_36_37_38_39_41_42_43_44_45_46_47_48_49_4A_4B_4C_4D_4E_4F_50_51_52_53_54_55_56_57_58_59_5A

# hex_lowercase bruteforce
./aes-brute-force FF00FF00_FF00FF00_FF00FF00_FF00FF00 007E1500_2800D2A6_ABF70088_09CF4F3C 3243F6A8_885A308D_313198A2_E0370734 3925841D_02DC09FB_DC118597_196A0B32 restrict 30_31_32_33_34_35_36_37_38_39_61_62_63_64_65_66_67_68_69_6A_6B_6C_6D_6E_6F_70_71_72_73_74_75_76_77_78_79_7A
````

### Bruteforcing Printable Character set

### Bruteforcing UTF-16LE Character set

```bash
# Combination of hex_lowercase and UTF-16LE
./aes-brute-force FF00FF00_FF00FF00_FF00FF00_FF00FF00 007E1500_2800D2A6_ABF70088_09CF4F3C 3243F6A8_885A308D_313198A2_E0370734 3925841D_02DC09FB_DC118597_196A0B32 restrict 30_31_32_33_34_35_36_37_38_39_61_62_63_64_65_66_67_68_69_6A_6B_6C_6D_6E_6F_70_71_72_73_74_75_76_77_78_79_7A
```

### Thanks

Thanks to [sebastien-riou/aes-brute-force](https://github.com/sebastien-riou/aes-brute-force) and [Botan]() open source projects that I used for the insperation, sanity checking and code.
