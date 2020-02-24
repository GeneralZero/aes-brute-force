from Crypto.Cipher import AES


if __name__ == '__main__':
	aes128key = open('/dev/urandom', 'rb').read(16)
	aes192key = open('/dev/urandom', 'rb').read(24)
	aes256key = open('/dev/urandom', 'rb').read(32)


	aes128 = AES.new(aes128key, AES.MODE_ECB)
	aes192 = AES.new(aes192key, AES.MODE_ECB)
	aes256 = AES.new(aes256key, AES.MODE_ECB)


	message = open('/dev/urandom', 'rb').read(16)

	cipher128 = aes128.encrypt(message)
	cipher192 = aes192.encrypt(message)
	cipher256 = aes256.encrypt(message)
	


	hex_plain = ", ".join(map(hex, bytearray(message)))
	hex_cipher128 = ", ".join(map(hex, bytearray(cipher128)))
	hex_cipher192 = ", ".join(map(hex, bytearray(cipher192)))
	hex_cipher256 = ", ".join(map(hex, bytearray(cipher256)))
	hex_key128 = ", ".join(map(hex, bytearray(aes128key)))
	hex_key192 = ", ".join(map(hex, bytearray(aes192key)))
	hex_key256 = ", ".join(map(hex, bytearray(aes256key)))


	print("//AES-128")
	print(f"uint8_t plain[]      = {{{hex_plain}}};")
	print(f"uint8_t enc_key[]    = {{{hex_key128}}};")
	print(f"uint8_t cipher[]     = {{{hex_cipher128}}};")
	print()

	print("//AES-192")
	print(f"uint8_t plain[]      = {{{hex_plain}}};")
	print(f"uint8_t enc_key[]    = {{{hex_key192}}};")
	print(f"uint8_t cipher[]     = {{{hex_cipher192}}};")
	print()


	print("//AES-256")
	print(f"uint8_t plain[]      = {{{hex_plain}}};")
	print(f"uint8_t enc_key[]    = {{{hex_key256}}};")
	print(f"uint8_t cipher[]     = {{{hex_cipher256}}};")

	#uint8_t plain[]      = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	#uint8_t enc_key[]    = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	#uint8_t cipher[]     = {0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32};
