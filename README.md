# aes-brute-force
Using Intel AES-NI and c++ threads to search AES keys. This suppports 128, 192 and 256 AES keys.
Sometimes side channel attacks recover most key bytes but not all. This project allows to brute force remaining bytes on commodity hardware. 

The AES-NI code has been taken from boton with some modifications.

## Measured performances
On a i7-9700K CPU @ 3.60GHz, 4 bytes (32 bits) takes about 3.4 seconds, 5 bytes (40 bits) takes about 15 mins. This is with a 128 bit key.

## Examples

### Bruteforcing Base64 Character set

### Bruteforcing Hex Character set

### Bruteforcing Printable Character set

### Bruteforcing UTF-16LE Character set

### Thanks

Thanks to [sebastien-riou/aes-brute-force](https://github.com/sebastien-riou/aes-brute-force) and [Botan]() for the open source projects that I used in making this project.
