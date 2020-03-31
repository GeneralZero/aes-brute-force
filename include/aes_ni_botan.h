#ifndef AES_NI_BOTAN 
#define AES_NI_BOTAN 

void aesni_128_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks, uint32_t* encryption_keys[44]);
void aesni_128_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks, uint32_t* decryption_keys[44]);
void aesni_128_key_schedule(const uint8_t key[], uint32_t* encryption_keys[44], uint32_t* decryption_keys[44]);

void aesni_192_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks, uint32_t* encryption_keys[52]);
void aesni_192_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks, uint32_t* decryption_keys[52]);
void aesni_192_key_schedule(const uint8_t input_key[], uint32_t const* encryption_keys[52], uint32_t const* decryption_keys[52]);

void aesni_256_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks, uint32_t const* encryption_keys[60]);
void aesni_256_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks, uint32_t const* decryption_keys[60]);
void aesni_256_key_schedule(const uint8_t input_key[], uint32_t const* encryption_keys[60], uint32_t const* decryption_keys[60]);

#endif