/*
* AES using AES-NI instructions
* (C) 2009,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <stdint.h>
#include <cstring>

#ifdef __x86_64
#include <wmmintrin.h>

inline void load_le(uint32_t* output, const uint8_t* input, size_t count)
{
	//Not dealing with endianness right now
	//std::memcpy(output, reinterpret_cast<const uint32_t*>(input), count);
	std::memcpy(output, input, count * sizeof(uint32_t));
}


__m128i aes_128_key_expansion(__m128i key, __m128i key_with_rcon)
{
	key_with_rcon = _mm_shuffle_epi32(key_with_rcon, _MM_SHUFFLE(3,3,3,3));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	return _mm_xor_si128(key, key_with_rcon);
}

void aes_192_key_expansion(__m128i* K1, __m128i* K2, __m128i key2_with_rcon,
									uint32_t out[], bool last)
{
	__m128i key1 = *K1;
	__m128i key2 = *K2;

	key2_with_rcon  = _mm_shuffle_epi32(key2_with_rcon, _MM_SHUFFLE(1,1,1,1));
	key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
	key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
	key1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
	key1 = _mm_xor_si128(key1, key2_with_rcon);

	*K1 = key1;
	_mm_storeu_si128(reinterpret_cast<__m128i*>(out), key1);

	if(last)
		return;

	key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
	key2 = _mm_xor_si128(key2, _mm_shuffle_epi32(key1, _MM_SHUFFLE(3,3,3,3)));

	*K2 = key2;
	out[4] = _mm_cvtsi128_si32(key2);
	out[5] = _mm_cvtsi128_si32(_mm_srli_si128(key2, 4));
}

/*
* The second half of the AES-256 key expansion (other half same as AES-128)
*/
__m128i aes_256_key_expansion(__m128i key, __m128i key2)
{
	__m128i key_with_rcon = _mm_aeskeygenassist_si128(key2, 0x00);
	key_with_rcon = _mm_shuffle_epi32(key_with_rcon, _MM_SHUFFLE(2,2,2,2));

	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	return _mm_xor_si128(key, key_with_rcon);
}

#define AES_ENC_4_ROUNDS(K)                     \
	do                                           \
		{                                         \
		B0 = _mm_aesenc_si128(B0, K);             \
		B1 = _mm_aesenc_si128(B1, K);             \
		B2 = _mm_aesenc_si128(B2, K);             \
		B3 = _mm_aesenc_si128(B3, K);             \
		} while(0)

#define AES_ENC_4_LAST_ROUNDS(K)                \
	do                                           \
		{                                         \
		B0 = _mm_aesenclast_si128(B0, K);         \
		B1 = _mm_aesenclast_si128(B1, K);         \
		B2 = _mm_aesenclast_si128(B2, K);         \
		B3 = _mm_aesenclast_si128(B3, K);         \
		} while(0)

#define AES_DEC_4_ROUNDS(K)                     \
	do                                           \
		{                                         \
		B0 = _mm_aesdec_si128(B0, K);             \
		B1 = _mm_aesdec_si128(B1, K);             \
		B2 = _mm_aesdec_si128(B2, K);             \
		B3 = _mm_aesdec_si128(B3, K);             \
		} while(0)

#define AES_DEC_4_LAST_ROUNDS(K)                \
	do                                           \
		{                                         \
		B0 = _mm_aesdeclast_si128(B0, K);         \
		B1 = _mm_aesdeclast_si128(B1, K);         \
		B2 = _mm_aesdeclast_si128(B2, K);         \
		B3 = _mm_aesdeclast_si128(B3, K);         \
		} while(0)

/*
* AES-128 Encryption
*/
void aesni_128_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks, uint32_t encryption_keys[44])
{
	const __m128i* in_mm = reinterpret_cast<const __m128i*>(in);
	__m128i* out_mm = reinterpret_cast<__m128i*>(out);

	const __m128i* key_mm = reinterpret_cast<const __m128i*>(encryption_keys);

	const __m128i K0  = _mm_loadu_si128(key_mm);
	const __m128i K1  = _mm_loadu_si128(key_mm + 1);
	const __m128i K2  = _mm_loadu_si128(key_mm + 2);
	const __m128i K3  = _mm_loadu_si128(key_mm + 3);
	const __m128i K4  = _mm_loadu_si128(key_mm + 4);
	const __m128i K5  = _mm_loadu_si128(key_mm + 5);
	const __m128i K6  = _mm_loadu_si128(key_mm + 6);
	const __m128i K7  = _mm_loadu_si128(key_mm + 7);
	const __m128i K8  = _mm_loadu_si128(key_mm + 8);
	const __m128i K9  = _mm_loadu_si128(key_mm + 9);
	const __m128i K10 = _mm_loadu_si128(key_mm + 10);

	while(blocks >= 4){
		__m128i B0 = _mm_loadu_si128(in_mm + 0);
		__m128i B1 = _mm_loadu_si128(in_mm + 1);
		__m128i B2 = _mm_loadu_si128(in_mm + 2);
		__m128i B3 = _mm_loadu_si128(in_mm + 3);

		B0 = _mm_xor_si128(B0, K0);
		B1 = _mm_xor_si128(B1, K0);
		B2 = _mm_xor_si128(B2, K0);
		B3 = _mm_xor_si128(B3, K0);

		AES_ENC_4_ROUNDS(K1);
		AES_ENC_4_ROUNDS(K2);
		AES_ENC_4_ROUNDS(K3);
		AES_ENC_4_ROUNDS(K4);
		AES_ENC_4_ROUNDS(K5);
		AES_ENC_4_ROUNDS(K6);
		AES_ENC_4_ROUNDS(K7);
		AES_ENC_4_ROUNDS(K8);
		AES_ENC_4_ROUNDS(K9);
		AES_ENC_4_LAST_ROUNDS(K10);

		_mm_storeu_si128(out_mm + 0, B0);
		_mm_storeu_si128(out_mm + 1, B1);
		_mm_storeu_si128(out_mm + 2, B2);
		_mm_storeu_si128(out_mm + 3, B3);

		blocks -= 4;
		in_mm += 4;
		out_mm += 4;
	}

	for(size_t i = 0; i != blocks; ++i)	{
		__m128i B = _mm_loadu_si128(in_mm + i);

		B = _mm_xor_si128(B, K0);

		B = _mm_aesenc_si128(B, K1);
		B = _mm_aesenc_si128(B, K2);
		B = _mm_aesenc_si128(B, K3);
		B = _mm_aesenc_si128(B, K4);
		B = _mm_aesenc_si128(B, K5);
		B = _mm_aesenc_si128(B, K6);
		B = _mm_aesenc_si128(B, K7);
		B = _mm_aesenc_si128(B, K8);
		B = _mm_aesenc_si128(B, K9);
		B = _mm_aesenclast_si128(B, K10);

		_mm_storeu_si128(out_mm + i, B);	
	}
}

/*
* AES-128 Decryption
*/
void aesni_128_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks, uint32_t decryption_keys[44])
{
	const __m128i* in_mm = reinterpret_cast<const __m128i*>(in);
	__m128i* out_mm = reinterpret_cast<__m128i*>(out);

	const __m128i* key_mm = reinterpret_cast<const __m128i*>(decryption_keys);

	const __m128i K0  = _mm_loadu_si128(key_mm);
	const __m128i K1  = _mm_loadu_si128(key_mm + 1);
	const __m128i K2  = _mm_loadu_si128(key_mm + 2);
	const __m128i K3  = _mm_loadu_si128(key_mm + 3);
	const __m128i K4  = _mm_loadu_si128(key_mm + 4);
	const __m128i K5  = _mm_loadu_si128(key_mm + 5);
	const __m128i K6  = _mm_loadu_si128(key_mm + 6);
	const __m128i K7  = _mm_loadu_si128(key_mm + 7);
	const __m128i K8  = _mm_loadu_si128(key_mm + 8);
	const __m128i K9  = _mm_loadu_si128(key_mm + 9);
	const __m128i K10 = _mm_loadu_si128(key_mm + 10);

	while(blocks >= 4){
		__m128i B0 = _mm_loadu_si128(in_mm + 0);
		__m128i B1 = _mm_loadu_si128(in_mm + 1);
		__m128i B2 = _mm_loadu_si128(in_mm + 2);
		__m128i B3 = _mm_loadu_si128(in_mm + 3);

		B0 = _mm_xor_si128(B0, K0);
		B1 = _mm_xor_si128(B1, K0);
		B2 = _mm_xor_si128(B2, K0);
		B3 = _mm_xor_si128(B3, K0);

		AES_DEC_4_ROUNDS(K1);
		AES_DEC_4_ROUNDS(K2);
		AES_DEC_4_ROUNDS(K3);
		AES_DEC_4_ROUNDS(K4);
		AES_DEC_4_ROUNDS(K5);
		AES_DEC_4_ROUNDS(K6);
		AES_DEC_4_ROUNDS(K7);
		AES_DEC_4_ROUNDS(K8);
		AES_DEC_4_ROUNDS(K9);
		AES_DEC_4_LAST_ROUNDS(K10);

		_mm_storeu_si128(out_mm + 0, B0);
		_mm_storeu_si128(out_mm + 1, B1);
		_mm_storeu_si128(out_mm + 2, B2);
		_mm_storeu_si128(out_mm + 3, B3);

		blocks -= 4;
		in_mm += 4;
		out_mm += 4;
	}

	for(size_t i = 0; i != blocks; ++i){
		__m128i B = _mm_loadu_si128(in_mm + i);

		B = _mm_xor_si128(B, K0);

		B = _mm_aesdec_si128(B, K1);
		B = _mm_aesdec_si128(B, K2);
		B = _mm_aesdec_si128(B, K3);
		B = _mm_aesdec_si128(B, K4);
		B = _mm_aesdec_si128(B, K5);
		B = _mm_aesdec_si128(B, K6);
		B = _mm_aesdec_si128(B, K7);
		B = _mm_aesdec_si128(B, K8);
		B = _mm_aesdec_si128(B, K9);
		B = _mm_aesdeclast_si128(B, K10);

		_mm_storeu_si128(out_mm + i, B);
	}
}

/*
* AES-128 Key Schedule
*/
void aesni_128_key_schedule(const uint8_t key[], uint32_t encryption_keys[44], uint32_t decryption_keys[44])
{
	#define AES_128_key_exp(K, RCON) \
		aes_128_key_expansion(K, _mm_aeskeygenassist_si128(K, RCON))

	const __m128i K0  = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
	const __m128i K1  = AES_128_key_exp(K0, 0x01);
	const __m128i K2  = AES_128_key_exp(K1, 0x02);
	const __m128i K3  = AES_128_key_exp(K2, 0x04);
	const __m128i K4  = AES_128_key_exp(K3, 0x08);
	const __m128i K5  = AES_128_key_exp(K4, 0x10);
	const __m128i K6  = AES_128_key_exp(K5, 0x20);
	const __m128i K7  = AES_128_key_exp(K6, 0x40);
	const __m128i K8  = AES_128_key_exp(K7, 0x80);
	const __m128i K9  = AES_128_key_exp(K8, 0x1B);
	const __m128i K10 = AES_128_key_exp(K9, 0x36);

	__m128i* EK_mm = reinterpret_cast<__m128i*>(encryption_keys);
	_mm_storeu_si128(EK_mm     , K0);
	_mm_storeu_si128(EK_mm +  1, K1);
	_mm_storeu_si128(EK_mm +  2, K2);
	_mm_storeu_si128(EK_mm +  3, K3);
	_mm_storeu_si128(EK_mm +  4, K4);
	_mm_storeu_si128(EK_mm +  5, K5);
	_mm_storeu_si128(EK_mm +  6, K6);
	_mm_storeu_si128(EK_mm +  7, K7);
	_mm_storeu_si128(EK_mm +  8, K8);
	_mm_storeu_si128(EK_mm +  9, K9);
	_mm_storeu_si128(EK_mm + 10, K10);

	// Now generate decryption keys

	__m128i* DK_mm = reinterpret_cast<__m128i*>(decryption_keys);
	_mm_storeu_si128(DK_mm     , K10);
	_mm_storeu_si128(DK_mm +  1, _mm_aesimc_si128(K9));
	_mm_storeu_si128(DK_mm +  2, _mm_aesimc_si128(K8));
	_mm_storeu_si128(DK_mm +  3, _mm_aesimc_si128(K7));
	_mm_storeu_si128(DK_mm +  4, _mm_aesimc_si128(K6));
	_mm_storeu_si128(DK_mm +  5, _mm_aesimc_si128(K5));
	_mm_storeu_si128(DK_mm +  6, _mm_aesimc_si128(K4));
	_mm_storeu_si128(DK_mm +  7, _mm_aesimc_si128(K3));
	_mm_storeu_si128(DK_mm +  8, _mm_aesimc_si128(K2));
	_mm_storeu_si128(DK_mm +  9, _mm_aesimc_si128(K1));
	_mm_storeu_si128(DK_mm + 10, K0);
}

void aesni_128_key_schedule_only_encryption(const uint8_t key[], uint32_t encryption_keys[44])
{
	#define AES_128_key_exp(K, RCON) \
		aes_128_key_expansion(K, _mm_aeskeygenassist_si128(K, RCON))

	const __m128i K0  = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
	const __m128i K1  = AES_128_key_exp(K0, 0x01);
	const __m128i K2  = AES_128_key_exp(K1, 0x02);
	const __m128i K3  = AES_128_key_exp(K2, 0x04);
	const __m128i K4  = AES_128_key_exp(K3, 0x08);
	const __m128i K5  = AES_128_key_exp(K4, 0x10);
	const __m128i K6  = AES_128_key_exp(K5, 0x20);
	const __m128i K7  = AES_128_key_exp(K6, 0x40);
	const __m128i K8  = AES_128_key_exp(K7, 0x80);
	const __m128i K9  = AES_128_key_exp(K8, 0x1B);
	const __m128i K10 = AES_128_key_exp(K9, 0x36);

	__m128i* EK_mm = reinterpret_cast<__m128i*>(encryption_keys);
	_mm_storeu_si128(EK_mm     , K0);
	_mm_storeu_si128(EK_mm +  1, K1);
	_mm_storeu_si128(EK_mm +  2, K2);
	_mm_storeu_si128(EK_mm +  3, K3);
	_mm_storeu_si128(EK_mm +  4, K4);
	_mm_storeu_si128(EK_mm +  5, K5);
	_mm_storeu_si128(EK_mm +  6, K6);
	_mm_storeu_si128(EK_mm +  7, K7);
	_mm_storeu_si128(EK_mm +  8, K8);
	_mm_storeu_si128(EK_mm +  9, K9);
	_mm_storeu_si128(EK_mm + 10, K10);
}

/*
* AES-192 Encryption
*/
void aesni_192_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks, uint32_t encryption_keys[52]) 
{
	const __m128i* in_mm = reinterpret_cast<const __m128i*>(in);
	__m128i* out_mm = reinterpret_cast<__m128i*>(out);

	const __m128i* key_mm = reinterpret_cast<const __m128i*>(encryption_keys);

	const __m128i K0  = _mm_loadu_si128(key_mm);
	const __m128i K1  = _mm_loadu_si128(key_mm + 1);
	const __m128i K2  = _mm_loadu_si128(key_mm + 2);
	const __m128i K3  = _mm_loadu_si128(key_mm + 3);
	const __m128i K4  = _mm_loadu_si128(key_mm + 4);
	const __m128i K5  = _mm_loadu_si128(key_mm + 5);
	const __m128i K6  = _mm_loadu_si128(key_mm + 6);
	const __m128i K7  = _mm_loadu_si128(key_mm + 7);
	const __m128i K8  = _mm_loadu_si128(key_mm + 8);
	const __m128i K9  = _mm_loadu_si128(key_mm + 9);
	const __m128i K10 = _mm_loadu_si128(key_mm + 10);
	const __m128i K11 = _mm_loadu_si128(key_mm + 11);
	const __m128i K12 = _mm_loadu_si128(key_mm + 12);

	while(blocks >= 4)
	{
		__m128i B0 = _mm_loadu_si128(in_mm + 0);
		__m128i B1 = _mm_loadu_si128(in_mm + 1);
		__m128i B2 = _mm_loadu_si128(in_mm + 2);
		__m128i B3 = _mm_loadu_si128(in_mm + 3);

		B0 = _mm_xor_si128(B0, K0);
		B1 = _mm_xor_si128(B1, K0);
		B2 = _mm_xor_si128(B2, K0);
		B3 = _mm_xor_si128(B3, K0);

		AES_ENC_4_ROUNDS(K1);
		AES_ENC_4_ROUNDS(K2);
		AES_ENC_4_ROUNDS(K3);
		AES_ENC_4_ROUNDS(K4);
		AES_ENC_4_ROUNDS(K5);
		AES_ENC_4_ROUNDS(K6);
		AES_ENC_4_ROUNDS(K7);
		AES_ENC_4_ROUNDS(K8);
		AES_ENC_4_ROUNDS(K9);
		AES_ENC_4_ROUNDS(K10);
		AES_ENC_4_ROUNDS(K11);
		AES_ENC_4_LAST_ROUNDS(K12);

		_mm_storeu_si128(out_mm + 0, B0);
		_mm_storeu_si128(out_mm + 1, B1);
		_mm_storeu_si128(out_mm + 2, B2);
		_mm_storeu_si128(out_mm + 3, B3);

		blocks -= 4;
		in_mm += 4;
		out_mm += 4;
	}

	for(size_t i = 0; i != blocks; ++i)
	{
		__m128i B = _mm_loadu_si128(in_mm + i);

		B = _mm_xor_si128(B, K0);

		B = _mm_aesenc_si128(B, K1);
		B = _mm_aesenc_si128(B, K2);
		B = _mm_aesenc_si128(B, K3);
		B = _mm_aesenc_si128(B, K4);
		B = _mm_aesenc_si128(B, K5);
		B = _mm_aesenc_si128(B, K6);
		B = _mm_aesenc_si128(B, K7);
		B = _mm_aesenc_si128(B, K8);
		B = _mm_aesenc_si128(B, K9);
		B = _mm_aesenc_si128(B, K10);
		B = _mm_aesenc_si128(B, K11);
		B = _mm_aesenclast_si128(B, K12);

		_mm_storeu_si128(out_mm + i, B);
	}
}

/*
* AES-192 Decryption
*/
void aesni_192_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks, uint32_t decryption_keys[52])
{
	const __m128i* in_mm = reinterpret_cast<const __m128i*>(in);
	__m128i* out_mm = reinterpret_cast<__m128i*>(out);

	const __m128i* key_mm = reinterpret_cast<const __m128i*>(decryption_keys);

	const __m128i K0  = _mm_loadu_si128(key_mm);
	const __m128i K1  = _mm_loadu_si128(key_mm + 1);
	const __m128i K2  = _mm_loadu_si128(key_mm + 2);
	const __m128i K3  = _mm_loadu_si128(key_mm + 3);
	const __m128i K4  = _mm_loadu_si128(key_mm + 4);
	const __m128i K5  = _mm_loadu_si128(key_mm + 5);
	const __m128i K6  = _mm_loadu_si128(key_mm + 6);
	const __m128i K7  = _mm_loadu_si128(key_mm + 7);
	const __m128i K8  = _mm_loadu_si128(key_mm + 8);
	const __m128i K9  = _mm_loadu_si128(key_mm + 9);
	const __m128i K10 = _mm_loadu_si128(key_mm + 10);
	const __m128i K11 = _mm_loadu_si128(key_mm + 11);
	const __m128i K12 = _mm_loadu_si128(key_mm + 12);

	while(blocks >= 4)
	{
		__m128i B0 = _mm_loadu_si128(in_mm + 0);
		__m128i B1 = _mm_loadu_si128(in_mm + 1);
		__m128i B2 = _mm_loadu_si128(in_mm + 2);
		__m128i B3 = _mm_loadu_si128(in_mm + 3);

		B0 = _mm_xor_si128(B0, K0);
		B1 = _mm_xor_si128(B1, K0);
		B2 = _mm_xor_si128(B2, K0);
		B3 = _mm_xor_si128(B3, K0);

		AES_DEC_4_ROUNDS(K1);
		AES_DEC_4_ROUNDS(K2);
		AES_DEC_4_ROUNDS(K3);
		AES_DEC_4_ROUNDS(K4);
		AES_DEC_4_ROUNDS(K5);
		AES_DEC_4_ROUNDS(K6);
		AES_DEC_4_ROUNDS(K7);
		AES_DEC_4_ROUNDS(K8);
		AES_DEC_4_ROUNDS(K9);
		AES_DEC_4_ROUNDS(K10);
		AES_DEC_4_ROUNDS(K11);
		AES_DEC_4_LAST_ROUNDS(K12);

		_mm_storeu_si128(out_mm + 0, B0);
		_mm_storeu_si128(out_mm + 1, B1);
		_mm_storeu_si128(out_mm + 2, B2);
		_mm_storeu_si128(out_mm + 3, B3);

		blocks -= 4;
		in_mm += 4;
		out_mm += 4;
	}

	for(size_t i = 0; i != blocks; ++i)
	{
		__m128i B = _mm_loadu_si128(in_mm + i);

		B = _mm_xor_si128(B, K0);

		B = _mm_aesdec_si128(B, K1);
		B = _mm_aesdec_si128(B, K2);
		B = _mm_aesdec_si128(B, K3);
		B = _mm_aesdec_si128(B, K4);
		B = _mm_aesdec_si128(B, K5);
		B = _mm_aesdec_si128(B, K6);
		B = _mm_aesdec_si128(B, K7);
		B = _mm_aesdec_si128(B, K8);
		B = _mm_aesdec_si128(B, K9);
		B = _mm_aesdec_si128(B, K10);
		B = _mm_aesdec_si128(B, K11);
		B = _mm_aesdeclast_si128(B, K12);

		_mm_storeu_si128(out_mm + i, B);
	}
}

/*
* AES-192 Key Schedule
*/
void aesni_192_key_schedule(const uint8_t input_key[], uint32_t encryption_keys[52], uint32_t decryption_keys[52])
{
	__m128i K0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input_key));
	__m128i K1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input_key + 8));
	K1 = _mm_srli_si128(K1, 8);

	load_le(encryption_keys, input_key, 6);

	#define AES_192_key_exp(RCON, EK_OFF)                         \
	  aes_192_key_expansion(&K0, &K1,                             \
									_mm_aeskeygenassist_si128(K1, RCON),  \
									(uint32_t*)(&encryption_keys[EK_OFF]), EK_OFF == 48)

	AES_192_key_exp(0x01, 6);
	AES_192_key_exp(0x02, 12);
	AES_192_key_exp(0x04, 18);
	AES_192_key_exp(0x08, 24);
	AES_192_key_exp(0x10, 30);
	AES_192_key_exp(0x20, 36);
	AES_192_key_exp(0x40, 42);
	AES_192_key_exp(0x80, 48);

	#undef AES_192_key_exp

	// Now generate decryption keys
	const __m128i* EK_mm = reinterpret_cast<const __m128i*>(encryption_keys);

	__m128i* DK_mm = reinterpret_cast<__m128i*>(decryption_keys);
	_mm_storeu_si128(DK_mm     , _mm_loadu_si128(EK_mm + 12));
	_mm_storeu_si128(DK_mm +  1, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 11)));
	_mm_storeu_si128(DK_mm +  2, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 10)));
	_mm_storeu_si128(DK_mm +  3, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 9)));
	_mm_storeu_si128(DK_mm +  4, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 8)));
	_mm_storeu_si128(DK_mm +  5, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 7)));
	_mm_storeu_si128(DK_mm +  6, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 6)));
	_mm_storeu_si128(DK_mm +  7, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 5)));
	_mm_storeu_si128(DK_mm +  8, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 4)));
	_mm_storeu_si128(DK_mm +  9, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 3)));
	_mm_storeu_si128(DK_mm + 10, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 2)));
	_mm_storeu_si128(DK_mm + 11, _mm_aesimc_si128(_mm_loadu_si128(EK_mm + 1)));
	_mm_storeu_si128(DK_mm + 12, _mm_loadu_si128(EK_mm + 0));
}

void aesni_192_key_schedule_only_encryption(const uint8_t input_key[], uint32_t encryption_keys[52])
{
	__m128i K0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input_key));
	__m128i K1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input_key + 8));
	K1 = _mm_srli_si128(K1, 8);

	load_le(encryption_keys, input_key, 6);

	#define AES_192_key_exp(RCON, EK_OFF)                         \
	  aes_192_key_expansion(&K0, &K1,                             \
									_mm_aeskeygenassist_si128(K1, RCON),  \
									(uint32_t*)(&encryption_keys[EK_OFF]), EK_OFF == 48)

	AES_192_key_exp(0x01, 6);
	AES_192_key_exp(0x02, 12);
	AES_192_key_exp(0x04, 18);
	AES_192_key_exp(0x08, 24);
	AES_192_key_exp(0x10, 30);
	AES_192_key_exp(0x20, 36);
	AES_192_key_exp(0x40, 42);
	AES_192_key_exp(0x80, 48);

	#undef AES_192_key_exp
}

/*
* AES-256 Encryption
*/
void aesni_256_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks, uint32_t encryption_keys[60])
{
	const __m128i* in_mm = reinterpret_cast<const __m128i*>(in);
	__m128i* out_mm = reinterpret_cast<__m128i*>(out);

	const __m128i* key_mm = reinterpret_cast<const __m128i*>(encryption_keys);

	const __m128i K0  = _mm_loadu_si128(key_mm);
	const __m128i K1  = _mm_loadu_si128(key_mm + 1);
	const __m128i K2  = _mm_loadu_si128(key_mm + 2);
	const __m128i K3  = _mm_loadu_si128(key_mm + 3);
	const __m128i K4  = _mm_loadu_si128(key_mm + 4);
	const __m128i K5  = _mm_loadu_si128(key_mm + 5);
	const __m128i K6  = _mm_loadu_si128(key_mm + 6);
	const __m128i K7  = _mm_loadu_si128(key_mm + 7);
	const __m128i K8  = _mm_loadu_si128(key_mm + 8);
	const __m128i K9  = _mm_loadu_si128(key_mm + 9);
	const __m128i K10 = _mm_loadu_si128(key_mm + 10);
	const __m128i K11 = _mm_loadu_si128(key_mm + 11);
	const __m128i K12 = _mm_loadu_si128(key_mm + 12);
	const __m128i K13 = _mm_loadu_si128(key_mm + 13);
	const __m128i K14 = _mm_loadu_si128(key_mm + 14);

	while(blocks >= 4)
	{
		__m128i B0 = _mm_loadu_si128(in_mm + 0);
		__m128i B1 = _mm_loadu_si128(in_mm + 1);
		__m128i B2 = _mm_loadu_si128(in_mm + 2);
		__m128i B3 = _mm_loadu_si128(in_mm + 3);

		B0 = _mm_xor_si128(B0, K0);
		B1 = _mm_xor_si128(B1, K0);
		B2 = _mm_xor_si128(B2, K0);
		B3 = _mm_xor_si128(B3, K0);

		AES_ENC_4_ROUNDS(K1);
		AES_ENC_4_ROUNDS(K2);
		AES_ENC_4_ROUNDS(K3);
		AES_ENC_4_ROUNDS(K4);
		AES_ENC_4_ROUNDS(K5);
		AES_ENC_4_ROUNDS(K6);
		AES_ENC_4_ROUNDS(K7);
		AES_ENC_4_ROUNDS(K8);
		AES_ENC_4_ROUNDS(K9);
		AES_ENC_4_ROUNDS(K10);
		AES_ENC_4_ROUNDS(K11);
		AES_ENC_4_ROUNDS(K12);
		AES_ENC_4_ROUNDS(K13);
		AES_ENC_4_LAST_ROUNDS(K14);

		_mm_storeu_si128(out_mm + 0, B0);
		_mm_storeu_si128(out_mm + 1, B1);
		_mm_storeu_si128(out_mm + 2, B2);
		_mm_storeu_si128(out_mm + 3, B3);

		blocks -= 4;
		in_mm += 4;
		out_mm += 4;
	}

	for(size_t i = 0; i != blocks; ++i)
	{
		__m128i B = _mm_loadu_si128(in_mm + i);

		B = _mm_xor_si128(B, K0);

		B = _mm_aesenc_si128(B, K1);
		B = _mm_aesenc_si128(B, K2);
		B = _mm_aesenc_si128(B, K3);
		B = _mm_aesenc_si128(B, K4);
		B = _mm_aesenc_si128(B, K5);
		B = _mm_aesenc_si128(B, K6);
		B = _mm_aesenc_si128(B, K7);
		B = _mm_aesenc_si128(B, K8);
		B = _mm_aesenc_si128(B, K9);
		B = _mm_aesenc_si128(B, K10);
		B = _mm_aesenc_si128(B, K11);
		B = _mm_aesenc_si128(B, K12);
		B = _mm_aesenc_si128(B, K13);
		B = _mm_aesenclast_si128(B, K14);

		_mm_storeu_si128(out_mm + i, B);
	}
}

/*
* AES-256 Decryption
*/
void aesni_256_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks, uint32_t decryption_keys[60])
{
	const __m128i* in_mm = reinterpret_cast<const __m128i*>(in);
	__m128i* out_mm = reinterpret_cast<__m128i*>(out);

	const __m128i* key_mm = reinterpret_cast<const __m128i*>(decryption_keys);

	const __m128i K0  = _mm_loadu_si128(key_mm);
	const __m128i K1  = _mm_loadu_si128(key_mm + 1);
	const __m128i K2  = _mm_loadu_si128(key_mm + 2);
	const __m128i K3  = _mm_loadu_si128(key_mm + 3);
	const __m128i K4  = _mm_loadu_si128(key_mm + 4);
	const __m128i K5  = _mm_loadu_si128(key_mm + 5);
	const __m128i K6  = _mm_loadu_si128(key_mm + 6);
	const __m128i K7  = _mm_loadu_si128(key_mm + 7);
	const __m128i K8  = _mm_loadu_si128(key_mm + 8);
	const __m128i K9  = _mm_loadu_si128(key_mm + 9);
	const __m128i K10 = _mm_loadu_si128(key_mm + 10);
	const __m128i K11 = _mm_loadu_si128(key_mm + 11);
	const __m128i K12 = _mm_loadu_si128(key_mm + 12);
	const __m128i K13 = _mm_loadu_si128(key_mm + 13);
	const __m128i K14 = _mm_loadu_si128(key_mm + 14);

	while(blocks >= 4)
	{
		__m128i B0 = _mm_loadu_si128(in_mm + 0);
		__m128i B1 = _mm_loadu_si128(in_mm + 1);
		__m128i B2 = _mm_loadu_si128(in_mm + 2);
		__m128i B3 = _mm_loadu_si128(in_mm + 3);

		B0 = _mm_xor_si128(B0, K0);
		B1 = _mm_xor_si128(B1, K0);
		B2 = _mm_xor_si128(B2, K0);
		B3 = _mm_xor_si128(B3, K0);

		AES_DEC_4_ROUNDS(K1);
		AES_DEC_4_ROUNDS(K2);
		AES_DEC_4_ROUNDS(K3);
		AES_DEC_4_ROUNDS(K4);
		AES_DEC_4_ROUNDS(K5);
		AES_DEC_4_ROUNDS(K6);
		AES_DEC_4_ROUNDS(K7);
		AES_DEC_4_ROUNDS(K8);
		AES_DEC_4_ROUNDS(K9);
		AES_DEC_4_ROUNDS(K10);
		AES_DEC_4_ROUNDS(K11);
		AES_DEC_4_ROUNDS(K12);
		AES_DEC_4_ROUNDS(K13);
		AES_DEC_4_LAST_ROUNDS(K14);

		_mm_storeu_si128(out_mm + 0, B0);
		_mm_storeu_si128(out_mm + 1, B1);
		_mm_storeu_si128(out_mm + 2, B2);
		_mm_storeu_si128(out_mm + 3, B3);

		blocks -= 4;
		in_mm += 4;
		out_mm += 4;
	}

	for(size_t i = 0; i != blocks; ++i)
	{
		__m128i B = _mm_loadu_si128(in_mm + i);

		B = _mm_xor_si128(B, K0);

		B = _mm_aesdec_si128(B, K1);
		B = _mm_aesdec_si128(B, K2);
		B = _mm_aesdec_si128(B, K3);
		B = _mm_aesdec_si128(B, K4);
		B = _mm_aesdec_si128(B, K5);
		B = _mm_aesdec_si128(B, K6);
		B = _mm_aesdec_si128(B, K7);
		B = _mm_aesdec_si128(B, K8);
		B = _mm_aesdec_si128(B, K9);
		B = _mm_aesdec_si128(B, K10);
		B = _mm_aesdec_si128(B, K11);
		B = _mm_aesdec_si128(B, K12);
		B = _mm_aesdec_si128(B, K13);
		B = _mm_aesdeclast_si128(B, K14);

		_mm_storeu_si128(out_mm + i, B);
	}
}

/*
* AES-256 Key Schedule
*/
void aesni_256_key_schedule(const uint8_t input_key[], uint32_t encryption_keys[60], uint32_t decryption_keys[60])
{

	const __m128i K0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input_key));
	const __m128i K1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input_key + 16));

	const __m128i K2 = aes_128_key_expansion(K0, _mm_aeskeygenassist_si128(K1, 0x01));
	const __m128i K3 = aes_256_key_expansion(K1, K2);

	const __m128i K4 = aes_128_key_expansion(K2, _mm_aeskeygenassist_si128(K3, 0x02));
	const __m128i K5 = aes_256_key_expansion(K3, K4);

	const __m128i K6 = aes_128_key_expansion(K4, _mm_aeskeygenassist_si128(K5, 0x04));
	const __m128i K7 = aes_256_key_expansion(K5, K6);

	const __m128i K8 = aes_128_key_expansion(K6, _mm_aeskeygenassist_si128(K7, 0x08));
	const __m128i K9 = aes_256_key_expansion(K7, K8);

	const __m128i K10 = aes_128_key_expansion(K8, _mm_aeskeygenassist_si128(K9, 0x10));
	const __m128i K11 = aes_256_key_expansion(K9, K10);

	const __m128i K12 = aes_128_key_expansion(K10, _mm_aeskeygenassist_si128(K11, 0x20));
	const __m128i K13 = aes_256_key_expansion(K11, K12);

	const __m128i K14 = aes_128_key_expansion(K12, _mm_aeskeygenassist_si128(K13, 0x40));

	__m128i* EK_mm = reinterpret_cast<__m128i*>(encryption_keys);
	_mm_storeu_si128(EK_mm     , K0);
	_mm_storeu_si128(EK_mm +  1, K1);
	_mm_storeu_si128(EK_mm +  2, K2);
	_mm_storeu_si128(EK_mm +  3, K3);
	_mm_storeu_si128(EK_mm +  4, K4);
	_mm_storeu_si128(EK_mm +  5, K5);
	_mm_storeu_si128(EK_mm +  6, K6);
	_mm_storeu_si128(EK_mm +  7, K7);
	_mm_storeu_si128(EK_mm +  8, K8);
	_mm_storeu_si128(EK_mm +  9, K9);
	_mm_storeu_si128(EK_mm + 10, K10);
	_mm_storeu_si128(EK_mm + 11, K11);
	_mm_storeu_si128(EK_mm + 12, K12);
	_mm_storeu_si128(EK_mm + 13, K13);
	_mm_storeu_si128(EK_mm + 14, K14);

	// Now generate decryption keys
	__m128i* DK_mm = reinterpret_cast<__m128i*>(decryption_keys);
	_mm_storeu_si128(DK_mm     , K14);
	_mm_storeu_si128(DK_mm +  1, _mm_aesimc_si128(K13));
	_mm_storeu_si128(DK_mm +  2, _mm_aesimc_si128(K12));
	_mm_storeu_si128(DK_mm +  3, _mm_aesimc_si128(K11));
	_mm_storeu_si128(DK_mm +  4, _mm_aesimc_si128(K10));
	_mm_storeu_si128(DK_mm +  5, _mm_aesimc_si128(K9));
	_mm_storeu_si128(DK_mm +  6, _mm_aesimc_si128(K8));
	_mm_storeu_si128(DK_mm +  7, _mm_aesimc_si128(K7));
	_mm_storeu_si128(DK_mm +  8, _mm_aesimc_si128(K6));
	_mm_storeu_si128(DK_mm +  9, _mm_aesimc_si128(K5));
	_mm_storeu_si128(DK_mm + 10, _mm_aesimc_si128(K4));
	_mm_storeu_si128(DK_mm + 11, _mm_aesimc_si128(K3));
	_mm_storeu_si128(DK_mm + 12, _mm_aesimc_si128(K2));
	_mm_storeu_si128(DK_mm + 13, _mm_aesimc_si128(K1));
	_mm_storeu_si128(DK_mm + 14, K0);
}

void aesni_256_key_schedule_only_encryption(const uint8_t input_key[], uint32_t encryption_keys[60])
{

	const __m128i K0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input_key));
	const __m128i K1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input_key + 16));

	const __m128i K2 = aes_128_key_expansion(K0, _mm_aeskeygenassist_si128(K1, 0x01));
	const __m128i K3 = aes_256_key_expansion(K1, K2);

	const __m128i K4 = aes_128_key_expansion(K2, _mm_aeskeygenassist_si128(K3, 0x02));
	const __m128i K5 = aes_256_key_expansion(K3, K4);

	const __m128i K6 = aes_128_key_expansion(K4, _mm_aeskeygenassist_si128(K5, 0x04));
	const __m128i K7 = aes_256_key_expansion(K5, K6);

	const __m128i K8 = aes_128_key_expansion(K6, _mm_aeskeygenassist_si128(K7, 0x08));
	const __m128i K9 = aes_256_key_expansion(K7, K8);

	const __m128i K10 = aes_128_key_expansion(K8, _mm_aeskeygenassist_si128(K9, 0x10));
	const __m128i K11 = aes_256_key_expansion(K9, K10);

	const __m128i K12 = aes_128_key_expansion(K10, _mm_aeskeygenassist_si128(K11, 0x20));
	const __m128i K13 = aes_256_key_expansion(K11, K12);

	const __m128i K14 = aes_128_key_expansion(K12, _mm_aeskeygenassist_si128(K13, 0x40));

	__m128i* EK_mm = reinterpret_cast<__m128i*>(encryption_keys);
	_mm_storeu_si128(EK_mm     , K0);
	_mm_storeu_si128(EK_mm +  1, K1);
	_mm_storeu_si128(EK_mm +  2, K2);
	_mm_storeu_si128(EK_mm +  3, K3);
	_mm_storeu_si128(EK_mm +  4, K4);
	_mm_storeu_si128(EK_mm +  5, K5);
	_mm_storeu_si128(EK_mm +  6, K6);
	_mm_storeu_si128(EK_mm +  7, K7);
	_mm_storeu_si128(EK_mm +  8, K8);
	_mm_storeu_si128(EK_mm +  9, K9);
	_mm_storeu_si128(EK_mm + 10, K10);
	_mm_storeu_si128(EK_mm + 11, K11);
	_mm_storeu_si128(EK_mm + 12, K12);
	_mm_storeu_si128(EK_mm + 13, K13);
	_mm_storeu_si128(EK_mm + 14, K14);
}

#undef AES_ENC_4_ROUNDS
#undef AES_ENC_4_LAST_ROUNDS
#undef AES_DEC_4_ROUNDS
#undef AES_DEC_4_LAST_ROUNDS


#else
#include <arm_neon.h>

inline void load_le(uint32_t* output, const uint8_t* input, size_t count)
{
	//Not dealing with endianness right now
	//std::memcpy(output, reinterpret_cast<const uint32_t*>(input), count);
	std::memcpy(output, input, count * sizeof(uint32_t));
}

uint8x16_t aeskeygenassist_si8x16(uint8x16_t a, const int rcon)
{
    // AESE does ShiftRows and SubBytes on A
    uint8x16_t u8 = vaeseq_u8(a, vdupq_n_u8(0));

    uint8x16_t dest = {
        // Undo ShiftRows step from AESE and extract X1 and X3
        u8[0x4], u8[0x1], u8[0xE], u8[0xB],  // SubBytes(X1)
        u8[0x1], u8[0xE], u8[0xB], u8[0x4],  // ROT(SubBytes(X1))
        u8[0xC], u8[0x9], u8[0x6], u8[0x3],  // SubBytes(X3)
        u8[0x9], u8[0x6], u8[0x3], u8[0xC],  // ROT(SubBytes(X3))
    };
    uint32x4_t r = {0, (unsigned) rcon, 0, (unsigned) rcon};
    return veorq_u8(dest, vreinterpretq_u8_u32(r));
}


uint8x16_t aes_128_key_expansion(uint8x16_t key, uint8x16_t key_with_rcon)
{
	//_mm_shuffle_epi32_splat((a), 3);
	//
	key_with_rcon = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(vreinterpretq_u32_u8(key_with_rcon), 3)));
	//vextq_s8((key, vdupq_n_u8(0), 16 - 4)
	key = veorq_u8(key, vextq_u8(vdupq_n_u8(0), key, 16 - 4));
	key = veorq_u8(key, vextq_u8(vdupq_n_u8(0), key, 16 - 4));
	key = veorq_u8(key, vextq_u8(vdupq_n_u8(0), key, 16 - 4));
	return veorq_u8(key, key_with_rcon);
}

void aes_192_key_expansion(uint8x16_t* K1, uint8x16_t* K2, uint8x16_t key2_with_rcon,
									uint32_t out[], bool last)
{
	uint8x16_t key1 = *K1;
	uint8x16_t key2 = *K2;

	key2_with_rcon = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(vreinterpretq_u32_u8(key2_with_rcon), 1)));
	key1 = veorq_u8(key1, vextq_u8(vdupq_n_u8(0), key1, 16 - 4));
	key1 = veorq_u8(key1, vextq_u8(vdupq_n_u8(0), key1, 16 - 4));
	key1 = veorq_u8(key1, vextq_u8(vdupq_n_u8(0), key1, 16 - 4));
	key1 = veorq_u8(key1, key2_with_rcon);

	*K1 = key1;
	vst1q_u8(reinterpret_cast<uint8_t*>(out), key1);

	if(last)
		return;

	key2 = veorq_u8(key2, vextq_u8(vdupq_n_u8(0), key2, 16 - 4));
	key2 = veorq_u8(key2, vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(vreinterpretq_u32_u8(key1), 3))));

	*K2 = key2;
	out[4] = vgetq_lane_u32(vreinterpretq_u32_u8(key2), 0);
	out[5] = vgetq_lane_u32(vreinterpretq_u32_u8(vextq_u8(key2, vdupq_n_u8(0), 16 - 12)), 0);
}

/*
* The second half of the AES-256 key expansion (other half same as AES-128)
*/
uint8x16_t aes_256_key_expansion(uint8x16_t key, uint8x16_t key2)
{
	uint8x16_t key_with_rcon = aeskeygenassist_si8x16(key2, 0x00);
	key_with_rcon = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(vreinterpretq_u32_u8(key_with_rcon), 2)));

	key = veorq_u8(key, vextq_u8(vdupq_n_u8(0), key, 16 - 4));
	key = veorq_u8(key, vextq_u8(vdupq_n_u8(0), key, 16 - 4));
	key = veorq_u8(key, vextq_u8(vdupq_n_u8(0), key, 16 - 4));
	return veorq_u8(key, key_with_rcon);
}

#define AES_ENC_4_ROUNDS(K)                \
   do                                      \
      {                                    \
      B0 = vaesmcq_u8(vaeseq_u8(B0, K));   \
      B1 = vaesmcq_u8(vaeseq_u8(B1, K));   \
      B2 = vaesmcq_u8(vaeseq_u8(B2, K));   \
      B3 = vaesmcq_u8(vaeseq_u8(B3, K));   \
      } while(0)

#define AES_ENC_4_LAST_ROUNDS(K, K2)       \
   do                                      \
      {                                    \
      B0 = veorq_u8(vaeseq_u8(B0, K), K2); \
      B1 = veorq_u8(vaeseq_u8(B1, K), K2); \
      B2 = veorq_u8(vaeseq_u8(B2, K), K2); \
      B3 = veorq_u8(vaeseq_u8(B3, K), K2); \
      } while(0)

#define AES_DEC_4_ROUNDS(K)                \
   do                                      \
      {                                    \
      B0 = vaesimcq_u8(vaesdq_u8(B0, K));  \
      B1 = vaesimcq_u8(vaesdq_u8(B1, K));  \
      B2 = vaesimcq_u8(vaesdq_u8(B2, K));  \
      B3 = vaesimcq_u8(vaesdq_u8(B3, K));  \
      } while(0)

#define AES_DEC_4_LAST_ROUNDS(K, K2)       \
   do                                      \
      {                                    \
      B0 = veorq_u8(vaesdq_u8(B0, K), K2); \
      B1 = veorq_u8(vaesdq_u8(B1, K), K2); \
      B2 = veorq_u8(vaesdq_u8(B2, K), K2); \
      B3 = veorq_u8(vaesdq_u8(B3, K), K2); \
      } while(0)

/*
* AES-128 Encryption
*/
void aesni_128_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks, uint32_t encryption_keys[44])
{
   const uint8_t *skey = reinterpret_cast<const uint8_t*>(encryption_keys);

   const uint8x16_t K0 = vld1q_u8(skey + 0*16);
   const uint8x16_t K1 = vld1q_u8(skey + 1*16);
   const uint8x16_t K2 = vld1q_u8(skey + 2*16);
   const uint8x16_t K3 = vld1q_u8(skey + 3*16);
   const uint8x16_t K4 = vld1q_u8(skey + 4*16);
   const uint8x16_t K5 = vld1q_u8(skey + 5*16);
   const uint8x16_t K6 = vld1q_u8(skey + 6*16);
   const uint8x16_t K7 = vld1q_u8(skey + 7*16);
   const uint8x16_t K8 = vld1q_u8(skey + 8*16);
   const uint8x16_t K9 = vld1q_u8(skey + 9*16);
   const uint8x16_t K10 = vld1q_u8(skey + 10*16);

	while(blocks >= 4){
		uint8x16_t B0 = vld1q_u8(in);
		uint8x16_t B1 = vld1q_u8(in+16);
		uint8x16_t B2 = vld1q_u8(in+32);
		uint8x16_t B3 = vld1q_u8(in+48);

		AES_ENC_4_ROUNDS(K0);
		AES_ENC_4_ROUNDS(K1);
		AES_ENC_4_ROUNDS(K2);
		AES_ENC_4_ROUNDS(K3);
		AES_ENC_4_ROUNDS(K4);
		AES_ENC_4_ROUNDS(K5);
		AES_ENC_4_ROUNDS(K6);
		AES_ENC_4_ROUNDS(K7);
		AES_ENC_4_ROUNDS(K8);
		AES_ENC_4_LAST_ROUNDS(K9, K10);

		vst1q_u8(out, B0);
		vst1q_u8(out+16, B1);
		vst1q_u8(out+32, B2);
		vst1q_u8(out+48, B3);

		in += 16*4;
		out += 16*4;
		blocks -= 4;
	}

	for(size_t i = 0; i != blocks; ++i)	{
		uint8x16_t B = vld1q_u8(in+16*i);
		B = vaesmcq_u8(vaeseq_u8(B, K0));
		B = vaesmcq_u8(vaeseq_u8(B, K1));
		B = vaesmcq_u8(vaeseq_u8(B, K2));
		B = vaesmcq_u8(vaeseq_u8(B, K3));
		B = vaesmcq_u8(vaeseq_u8(B, K4));
		B = vaesmcq_u8(vaeseq_u8(B, K5));
		B = vaesmcq_u8(vaeseq_u8(B, K6));
		B = vaesmcq_u8(vaeseq_u8(B, K7));
		B = vaesmcq_u8(vaeseq_u8(B, K8));
		B = veorq_u8(vaeseq_u8(B, K9), K10);
		vst1q_u8(out+16*i, B);
	}
}

/*
* AES-128 Decryption
*/
void aesni_128_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks, uint32_t decryption_keys[44])
{
	const uint8_t *skey = reinterpret_cast<const uint8_t*>(decryption_keys);

	const uint8x16_t K0 = vld1q_u8(skey + 0*16);
	const uint8x16_t K1 = vld1q_u8(skey + 1*16);
	const uint8x16_t K2 = vld1q_u8(skey + 2*16);
	const uint8x16_t K3 = vld1q_u8(skey + 3*16);
	const uint8x16_t K4 = vld1q_u8(skey + 4*16);
	const uint8x16_t K5 = vld1q_u8(skey + 5*16);
	const uint8x16_t K6 = vld1q_u8(skey + 6*16);
	const uint8x16_t K7 = vld1q_u8(skey + 7*16);
	const uint8x16_t K8 = vld1q_u8(skey + 8*16);
	const uint8x16_t K9 = vld1q_u8(skey + 9*16);
	const uint8x16_t K10 = vld1q_u8(skey + 10*16);

	while(blocks >= 4){
		uint8x16_t B0 = vld1q_u8(in);
		uint8x16_t B1 = vld1q_u8(in+16);
		uint8x16_t B2 = vld1q_u8(in+32);
		uint8x16_t B3 = vld1q_u8(in+48);

		AES_DEC_4_ROUNDS(K0);
		AES_DEC_4_ROUNDS(K1);
		AES_DEC_4_ROUNDS(K2);
		AES_DEC_4_ROUNDS(K3);
		AES_DEC_4_ROUNDS(K4);
		AES_DEC_4_ROUNDS(K5);
		AES_DEC_4_ROUNDS(K6);
		AES_DEC_4_ROUNDS(K7);
		AES_DEC_4_ROUNDS(K8);
		AES_DEC_4_LAST_ROUNDS(K9, K10);

		vst1q_u8(out, B0);
		vst1q_u8(out+16, B1);
		vst1q_u8(out+32, B2);
		vst1q_u8(out+48, B3);

		in += 16*4;
		out += 16*4;
		blocks -= 4;
	}

	for(size_t i = 0; i != blocks; ++i){
		uint8x16_t B = vld1q_u8(in+16*i);
		B = vaesimcq_u8(vaesdq_u8(B, K0));
		B = vaesimcq_u8(vaesdq_u8(B, K1));
		B = vaesimcq_u8(vaesdq_u8(B, K2));
		B = vaesimcq_u8(vaesdq_u8(B, K3));
		B = vaesimcq_u8(vaesdq_u8(B, K4));
		B = vaesimcq_u8(vaesdq_u8(B, K5));
		B = vaesimcq_u8(vaesdq_u8(B, K6));
		B = vaesimcq_u8(vaesdq_u8(B, K7));
		B = vaesimcq_u8(vaesdq_u8(B, K8));
		B = veorq_u8(vaesdq_u8(B, K9), K10);
		vst1q_u8(out+16*i, B);
	}
}

/*
* AES-128 Key Schedule
*/
void aesni_128_key_schedule(const uint8_t key[], uint32_t encryption_keys[44], uint32_t decryption_keys[44])
{
	#define AES_128_key_exp(K, RCON) \
		aes_128_key_expansion(K, aeskeygenassist_si8x16(K, RCON))

	const uint8x16_t K0  = vld1q_u8(key);
	const uint8x16_t K1  = AES_128_key_exp(K0, 0x01);
	const uint8x16_t K2  = AES_128_key_exp(K1, 0x02);
	const uint8x16_t K3  = AES_128_key_exp(K2, 0x04);
	const uint8x16_t K4  = AES_128_key_exp(K3, 0x08);
	const uint8x16_t K5  = AES_128_key_exp(K4, 0x10);
	const uint8x16_t K6  = AES_128_key_exp(K5, 0x20);
	const uint8x16_t K7  = AES_128_key_exp(K6, 0x40);
	const uint8x16_t K8  = AES_128_key_exp(K7, 0x80);
	const uint8x16_t K9  = AES_128_key_exp(K8, 0x1B);
	const uint8x16_t K10 = AES_128_key_exp(K9, 0x36);

	uint8x16_t* EK_mm = reinterpret_cast<uint8x16_t*>(encryption_keys);
	EK_mm[0]  = K0;
	EK_mm[1]  = K1;
	EK_mm[2]  = K2;
	EK_mm[3]  = K3;
	EK_mm[4]  = K4;
	EK_mm[5]  = K5;
	EK_mm[6]  = K6;
	EK_mm[7]  = K7;
	EK_mm[8]  = K8;
	EK_mm[9]  = K9;
	EK_mm[10] = K10;

	// Now generate decryption keys

	uint8x16_t* DK_mm = reinterpret_cast<uint8x16_t*>(decryption_keys);
	DK_mm[0]  = K10;
	DK_mm[1]  = vaesimcq_u8(K9);
	DK_mm[2]  = vaesimcq_u8(K8);
	DK_mm[3]  = vaesimcq_u8(K7);
	DK_mm[4]  = vaesimcq_u8(K6);
	DK_mm[5]  = vaesimcq_u8(K5);
	DK_mm[6]  = vaesimcq_u8(K4);
	DK_mm[7]  = vaesimcq_u8(K3);
	DK_mm[8]  = vaesimcq_u8(K2);
	DK_mm[9]  = vaesimcq_u8(K1);
	DK_mm[10] = K0;
}

void aesni_128_key_schedule_only_encryption(const uint8_t key[], uint32_t encryption_keys[44])
{
	#define AES_128_key_exp(K, RCON) \
		aes_128_key_expansion(K, aeskeygenassist_si8x16(K, RCON))

	const uint8x16_t K0  = vld1q_u8(key);
	const uint8x16_t K1  = AES_128_key_exp(K0, 0x01);
	const uint8x16_t K2  = AES_128_key_exp(K1, 0x02);
	const uint8x16_t K3  = AES_128_key_exp(K2, 0x04);
	const uint8x16_t K4  = AES_128_key_exp(K3, 0x08);
	const uint8x16_t K5  = AES_128_key_exp(K4, 0x10);
	const uint8x16_t K6  = AES_128_key_exp(K5, 0x20);
	const uint8x16_t K7  = AES_128_key_exp(K6, 0x40);
	const uint8x16_t K8  = AES_128_key_exp(K7, 0x80);
	const uint8x16_t K9  = AES_128_key_exp(K8, 0x1B);
	const uint8x16_t K10 = AES_128_key_exp(K9, 0x36);

	uint8x16_t* EK_mm = reinterpret_cast<uint8x16_t*>(encryption_keys);
	EK_mm[0]  = K0;
	EK_mm[1]  = K1;
	EK_mm[2]  = K2;
	EK_mm[3]  = K3;
	EK_mm[4]  = K4;
	EK_mm[5]  = K5;
	EK_mm[6]  = K6;
	EK_mm[7]  = K7;
	EK_mm[8]  = K8;
	EK_mm[9]  = K9;
	EK_mm[10] = K10;
}

/*
* AES-192 Encryption
*/
void aesni_192_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks, uint32_t encryption_keys[52]) 
{
	const uint8_t *skey = reinterpret_cast<const uint8_t*>(encryption_keys);

	const uint8x16_t K0 =  vld1q_u8(skey + 0*16);
	const uint8x16_t K1 =  vld1q_u8(skey + 1*16);
	const uint8x16_t K2 =  vld1q_u8(skey + 2*16);
	const uint8x16_t K3 =  vld1q_u8(skey + 3*16);
	const uint8x16_t K4 =  vld1q_u8(skey + 4*16);
	const uint8x16_t K5 =  vld1q_u8(skey + 5*16);
	const uint8x16_t K6 =  vld1q_u8(skey + 6*16);
	const uint8x16_t K7 =  vld1q_u8(skey + 7*16);
	const uint8x16_t K8 =  vld1q_u8(skey + 8*16);
	const uint8x16_t K9 =  vld1q_u8(skey + 9*16);
	const uint8x16_t K10 = vld1q_u8(skey + 10*16);
	const uint8x16_t K11 = vld1q_u8(skey + 11*16);
	const uint8x16_t K12 = vld1q_u8(skey + 12*16);

	while(blocks >= 4)
	{
		uint8x16_t B0 = vld1q_u8(in);
		uint8x16_t B1 = vld1q_u8(in+16);
		uint8x16_t B2 = vld1q_u8(in+32);
		uint8x16_t B3 = vld1q_u8(in+48);

		AES_ENC_4_ROUNDS(K0);
		AES_ENC_4_ROUNDS(K1);
		AES_ENC_4_ROUNDS(K2);
		AES_ENC_4_ROUNDS(K3);
		AES_ENC_4_ROUNDS(K4);
		AES_ENC_4_ROUNDS(K5);
		AES_ENC_4_ROUNDS(K6);
		AES_ENC_4_ROUNDS(K7);
		AES_ENC_4_ROUNDS(K8);
		AES_ENC_4_ROUNDS(K9);
		AES_ENC_4_ROUNDS(K10);
		AES_ENC_4_LAST_ROUNDS(K11, K12);

		vst1q_u8(out, B0);
		vst1q_u8(out+16, B1);
		vst1q_u8(out+32, B2);
		vst1q_u8(out+48, B3);

		in += 16*4;
		out += 16*4;
		blocks -= 4;
	}

	for(size_t i = 0; i != blocks; ++i)
	{
		uint8x16_t B = vld1q_u8(in+16*i);
		B = vaesmcq_u8(vaeseq_u8(B, K0));
		B = vaesmcq_u8(vaeseq_u8(B, K1));
		B = vaesmcq_u8(vaeseq_u8(B, K2));
		B = vaesmcq_u8(vaeseq_u8(B, K3));
		B = vaesmcq_u8(vaeseq_u8(B, K4));
		B = vaesmcq_u8(vaeseq_u8(B, K5));
		B = vaesmcq_u8(vaeseq_u8(B, K6));
		B = vaesmcq_u8(vaeseq_u8(B, K7));
		B = vaesmcq_u8(vaeseq_u8(B, K8));
		B = vaesmcq_u8(vaeseq_u8(B, K9));
		B = vaesmcq_u8(vaeseq_u8(B, K10));
		B = veorq_u8(vaeseq_u8(B, K11), K12);
		vst1q_u8(out+16*i, B);
	}
}

/*
* AES-192 Decryption
*/
void aesni_192_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks, uint32_t decryption_keys[52])
{
	const uint8_t *skey = reinterpret_cast<const uint8_t*>(decryption_keys);

	const uint8x16_t K0 = vld1q_u8(skey + 0*16);
	const uint8x16_t K1 = vld1q_u8(skey + 1*16);
	const uint8x16_t K2 = vld1q_u8(skey + 2*16);
	const uint8x16_t K3 = vld1q_u8(skey + 3*16);
	const uint8x16_t K4 = vld1q_u8(skey + 4*16);
	const uint8x16_t K5 = vld1q_u8(skey + 5*16);
	const uint8x16_t K6 = vld1q_u8(skey + 6*16);
	const uint8x16_t K7 = vld1q_u8(skey + 7*16);
	const uint8x16_t K8 = vld1q_u8(skey + 8*16);
	const uint8x16_t K9 = vld1q_u8(skey + 9*16);
	const uint8x16_t K10 = vld1q_u8(skey + 10*16);
	const uint8x16_t K11 = vld1q_u8(skey + 11*16);
	const uint8x16_t K12 = vld1q_u8(skey + 12*16);

	while(blocks >= 4)
	{
		uint8x16_t B0 = vld1q_u8(in);
		uint8x16_t B1 = vld1q_u8(in+16);
		uint8x16_t B2 = vld1q_u8(in+32);
		uint8x16_t B3 = vld1q_u8(in+48);

		AES_DEC_4_ROUNDS(K0);
		AES_DEC_4_ROUNDS(K1);
		AES_DEC_4_ROUNDS(K2);
		AES_DEC_4_ROUNDS(K3);
		AES_DEC_4_ROUNDS(K4);
		AES_DEC_4_ROUNDS(K5);
		AES_DEC_4_ROUNDS(K6);
		AES_DEC_4_ROUNDS(K7);
		AES_DEC_4_ROUNDS(K8);
		AES_DEC_4_ROUNDS(K9);
		AES_DEC_4_ROUNDS(K10);
		AES_DEC_4_LAST_ROUNDS(K11, K12);

		vst1q_u8(out, B0);
		vst1q_u8(out+16, B1);
		vst1q_u8(out+32, B2);
		vst1q_u8(out+48, B3);

		in += 16*4;
		out += 16*4;
		blocks -= 4;
	}

	for(size_t i = 0; i != blocks; ++i)
	{
		uint8x16_t B = vld1q_u8(in+16*i);
		B = vaesimcq_u8(vaesdq_u8(B, K0));
		B = vaesimcq_u8(vaesdq_u8(B, K1));
		B = vaesimcq_u8(vaesdq_u8(B, K2));
		B = vaesimcq_u8(vaesdq_u8(B, K3));
		B = vaesimcq_u8(vaesdq_u8(B, K4));
		B = vaesimcq_u8(vaesdq_u8(B, K5));
		B = vaesimcq_u8(vaesdq_u8(B, K6));
		B = vaesimcq_u8(vaesdq_u8(B, K7));
		B = vaesimcq_u8(vaesdq_u8(B, K8));
		B = vaesimcq_u8(vaesdq_u8(B, K9));
		B = vaesimcq_u8(vaesdq_u8(B, K10));
		B = veorq_u8(vaesdq_u8(B, K11), K12);
		vst1q_u8(out+16*i, B);
	}
}

/*
* AES-192 Key Schedule
*/
void aesni_192_key_schedule(const uint8_t input_key[], uint32_t encryption_keys[52], uint32_t decryption_keys[52])
{
	uint8x16_t K0 = vld1q_u8(input_key);
	uint8x16_t K1 = vld1q_u8(input_key + 8);
	//vextq_u8
	K1 = vextq_u8(K1, vdupq_n_u8(0), 16 - 8);

	load_le(encryption_keys, input_key, 6);

	#define AES_192_key_exp(RCON, EK_OFF)                         \
	  aes_192_key_expansion(&K0, &K1,                             \
									aeskeygenassist_si8x16(K1, RCON),  \
									(uint32_t*)(&encryption_keys[EK_OFF]), EK_OFF == 48)

	AES_192_key_exp(0x01, 6);
	AES_192_key_exp(0x02, 12);
	AES_192_key_exp(0x04, 18);
	AES_192_key_exp(0x08, 24);
	AES_192_key_exp(0x10, 30);
	AES_192_key_exp(0x20, 36);
	AES_192_key_exp(0x40, 42);
	AES_192_key_exp(0x80, 48);

	#undef AES_192_key_exp

	// Now generate decryption keys
	const uint8x16_t* EK_mm = reinterpret_cast<const uint8x16_t*>(encryption_keys);

	uint8x16_t* DK_mm = reinterpret_cast<uint8x16_t*>(decryption_keys);
	DK_mm[0]  = EK_mm[12];
	DK_mm[1]  = vaesimcq_u8(EK_mm[11]);
	DK_mm[2]  = vaesimcq_u8(EK_mm[10]);
	DK_mm[3]  = vaesimcq_u8(EK_mm[9]);
	DK_mm[4]  = vaesimcq_u8(EK_mm[8]);
	DK_mm[5]  = vaesimcq_u8(EK_mm[7]);
	DK_mm[6]  = vaesimcq_u8(EK_mm[6]);
	DK_mm[7]  = vaesimcq_u8(EK_mm[5]);
	DK_mm[8]  = vaesimcq_u8(EK_mm[4]);
	DK_mm[9]  = vaesimcq_u8(EK_mm[3]);
	DK_mm[10] = vaesimcq_u8(EK_mm[2]);
	DK_mm[11] = vaesimcq_u8(EK_mm[1]);
	DK_mm[12] = EK_mm[0];
}

void aesni_192_key_schedule_only_encryption(const uint8_t input_key[], uint32_t encryption_keys[52])
{
	uint8x16_t K0 = vld1q_u8(input_key);
	uint8x16_t K1 = vld1q_u8(input_key + 8);
	K1 = vextq_u8(vdupq_n_u8(0), K1, 16 - 4);

	load_le(encryption_keys, input_key, 6);

	#define AES_192_key_exp(RCON, EK_OFF)                         \
	  aes_192_key_expansion(&K0, &K1,                             \
									aeskeygenassist_si8x16(K1, RCON),  \
									(uint32_t*)(&encryption_keys[EK_OFF]), EK_OFF == 48)

	AES_192_key_exp(0x01, 6);
	AES_192_key_exp(0x02, 12);
	AES_192_key_exp(0x04, 18);
	AES_192_key_exp(0x08, 24);
	AES_192_key_exp(0x10, 30);
	AES_192_key_exp(0x20, 36);
	AES_192_key_exp(0x40, 42);
	AES_192_key_exp(0x80, 48);

	#undef AES_192_key_exp
}

/*
* AES-256 Encryption
*/
void aesni_256_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks, uint32_t encryption_keys[60])
{
	const uint8_t *skey = reinterpret_cast<const uint8_t*>(encryption_keys);

	const uint8x16_t K0 = vld1q_u8(skey + 0*16);
	const uint8x16_t K1 = vld1q_u8(skey + 1*16);
	const uint8x16_t K2 = vld1q_u8(skey + 2*16);
	const uint8x16_t K3 = vld1q_u8(skey + 3*16);
	const uint8x16_t K4 = vld1q_u8(skey + 4*16);
	const uint8x16_t K5 = vld1q_u8(skey + 5*16);
	const uint8x16_t K6 = vld1q_u8(skey + 6*16);
	const uint8x16_t K7 = vld1q_u8(skey + 7*16);
	const uint8x16_t K8 = vld1q_u8(skey + 8*16);
	const uint8x16_t K9 = vld1q_u8(skey + 9*16);
	const uint8x16_t K10 = vld1q_u8(skey + 10*16);
	const uint8x16_t K11 = vld1q_u8(skey + 11*16);
	const uint8x16_t K12 = vld1q_u8(skey + 12*16);
	const uint8x16_t K13 = vld1q_u8(skey + 13*16);
	const uint8x16_t K14 = vld1q_u8(skey + 14*16);

	while(blocks >= 4)
	{
		uint8x16_t B0 = vld1q_u8(in);
		uint8x16_t B1 = vld1q_u8(in+16);
		uint8x16_t B2 = vld1q_u8(in+32);
		uint8x16_t B3 = vld1q_u8(in+48);

		AES_ENC_4_ROUNDS(K0);
		AES_ENC_4_ROUNDS(K1);
		AES_ENC_4_ROUNDS(K2);
		AES_ENC_4_ROUNDS(K3);
		AES_ENC_4_ROUNDS(K4);
		AES_ENC_4_ROUNDS(K5);
		AES_ENC_4_ROUNDS(K6);
		AES_ENC_4_ROUNDS(K7);
		AES_ENC_4_ROUNDS(K8);
		AES_ENC_4_ROUNDS(K9);
		AES_ENC_4_ROUNDS(K10);
		AES_ENC_4_ROUNDS(K11);
		AES_ENC_4_ROUNDS(K12);
		AES_ENC_4_LAST_ROUNDS(K13, K14);

		vst1q_u8(out, B0);
		vst1q_u8(out+16, B1);
		vst1q_u8(out+32, B2);
		vst1q_u8(out+48, B3);

		in += 16*4;
		out += 16*4;
		blocks -= 4;
	}

	for(size_t i = 0; i != blocks; ++i)
	{
		uint8x16_t B = vld1q_u8(in+16*i);
		B = vaesmcq_u8(vaeseq_u8(B, K0));
		B = vaesmcq_u8(vaeseq_u8(B, K1));
		B = vaesmcq_u8(vaeseq_u8(B, K2));
		B = vaesmcq_u8(vaeseq_u8(B, K3));
		B = vaesmcq_u8(vaeseq_u8(B, K4));
		B = vaesmcq_u8(vaeseq_u8(B, K5));
		B = vaesmcq_u8(vaeseq_u8(B, K6));
		B = vaesmcq_u8(vaeseq_u8(B, K7));
		B = vaesmcq_u8(vaeseq_u8(B, K8));
		B = vaesmcq_u8(vaeseq_u8(B, K9));
		B = vaesmcq_u8(vaeseq_u8(B, K10));
		B = vaesmcq_u8(vaeseq_u8(B, K11));
		B = vaesmcq_u8(vaeseq_u8(B, K12));
		B = veorq_u8(vaeseq_u8(B, K13), K14);
		vst1q_u8(out+16*i, B);
	}
}

/*
* AES-256 Decryption
*/
void aesni_256_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks, uint32_t decryption_keys[60])
{
	const uint8_t *skey = reinterpret_cast<const uint8_t*>(decryption_keys);

	const uint8x16_t K0 = vld1q_u8(skey + 0*16);
	const uint8x16_t K1 = vld1q_u8(skey + 1*16);
	const uint8x16_t K2 = vld1q_u8(skey + 2*16);
	const uint8x16_t K3 = vld1q_u8(skey + 3*16);
	const uint8x16_t K4 = vld1q_u8(skey + 4*16);
	const uint8x16_t K5 = vld1q_u8(skey + 5*16);
	const uint8x16_t K6 = vld1q_u8(skey + 6*16);
	const uint8x16_t K7 = vld1q_u8(skey + 7*16);
	const uint8x16_t K8 = vld1q_u8(skey + 8*16);
	const uint8x16_t K9 = vld1q_u8(skey + 9*16);
	const uint8x16_t K10 = vld1q_u8(skey + 10*16);
	const uint8x16_t K11 = vld1q_u8(skey + 11*16);
	const uint8x16_t K12 = vld1q_u8(skey + 12*16);
	const uint8x16_t K13 = vld1q_u8(skey + 13*16);
	const uint8x16_t K14 = vld1q_u8(skey + 14*16);

	while(blocks >= 4)
	{
		uint8x16_t B0 = vld1q_u8(in);
		uint8x16_t B1 = vld1q_u8(in+16);
		uint8x16_t B2 = vld1q_u8(in+32);
		uint8x16_t B3 = vld1q_u8(in+48);

		AES_DEC_4_ROUNDS(K0);
		AES_DEC_4_ROUNDS(K1);
		AES_DEC_4_ROUNDS(K2);
		AES_DEC_4_ROUNDS(K3);
		AES_DEC_4_ROUNDS(K4);
		AES_DEC_4_ROUNDS(K5);
		AES_DEC_4_ROUNDS(K6);
		AES_DEC_4_ROUNDS(K7);
		AES_DEC_4_ROUNDS(K8);
		AES_DEC_4_ROUNDS(K9);
		AES_DEC_4_ROUNDS(K10);
		AES_DEC_4_ROUNDS(K11);
		AES_DEC_4_ROUNDS(K12);
		AES_DEC_4_LAST_ROUNDS(K13, K14);

		vst1q_u8(out, B0);
		vst1q_u8(out+16, B1);
		vst1q_u8(out+32, B2);
		vst1q_u8(out+48, B3);

		in += 16*4;
		out += 16*4;
		blocks -= 4;
	}

	for(size_t i = 0; i != blocks; ++i)
	{
		uint8x16_t B = vld1q_u8(in+16*i);
		B = vaesimcq_u8(vaesdq_u8(B, K0));
		B = vaesimcq_u8(vaesdq_u8(B, K1));
		B = vaesimcq_u8(vaesdq_u8(B, K2));
		B = vaesimcq_u8(vaesdq_u8(B, K3));
		B = vaesimcq_u8(vaesdq_u8(B, K4));
		B = vaesimcq_u8(vaesdq_u8(B, K5));
		B = vaesimcq_u8(vaesdq_u8(B, K6));
		B = vaesimcq_u8(vaesdq_u8(B, K7));
		B = vaesimcq_u8(vaesdq_u8(B, K8));
		B = vaesimcq_u8(vaesdq_u8(B, K9));
		B = vaesimcq_u8(vaesdq_u8(B, K10));
		B = vaesimcq_u8(vaesdq_u8(B, K11));
		B = vaesimcq_u8(vaesdq_u8(B, K12));
		B = veorq_u8(vaesdq_u8(B, K13), K14);
		vst1q_u8(out+16*i, B);
	}
}

/*
* AES-256 Key Schedule
*/
void aesni_256_key_schedule(const uint8_t input_key[], uint32_t encryption_keys[60], uint32_t decryption_keys[60])
{

	const uint8x16_t K0 = vld1q_u8(input_key);
	const uint8x16_t K1 = vld1q_u8(input_key + 16);

	const uint8x16_t K2 = aes_128_key_expansion(K0, aeskeygenassist_si8x16(K1, 0x01));
	const uint8x16_t K3 = aes_256_key_expansion(K1, K2);

	const uint8x16_t K4 = aes_128_key_expansion(K2, aeskeygenassist_si8x16(K3, 0x02));
	const uint8x16_t K5 = aes_256_key_expansion(K3, K4);

	const uint8x16_t K6 = aes_128_key_expansion(K4, aeskeygenassist_si8x16(K5, 0x04));
	const uint8x16_t K7 = aes_256_key_expansion(K5, K6);

	const uint8x16_t K8 = aes_128_key_expansion(K6, aeskeygenassist_si8x16(K7, 0x08));
	const uint8x16_t K9 = aes_256_key_expansion(K7, K8);

	const uint8x16_t K10 = aes_128_key_expansion(K8, aeskeygenassist_si8x16(K9, 0x10));
	const uint8x16_t K11 = aes_256_key_expansion(K9, K10);

	const uint8x16_t K12 = aes_128_key_expansion(K10, aeskeygenassist_si8x16(K11, 0x20));
	const uint8x16_t K13 = aes_256_key_expansion(K11, K12);

	const uint8x16_t K14 = aes_128_key_expansion(K12, aeskeygenassist_si8x16(K13, 0x40));

	uint8x16_t* EK_mm = reinterpret_cast<uint8x16_t*>(encryption_keys);
	EK_mm[0] =  K0;
	EK_mm[1] =  K1;
	EK_mm[2] =  K2;
	EK_mm[3] =  K3;
	EK_mm[4] =  K4;
	EK_mm[5] =  K5;
	EK_mm[6] =  K6;
	EK_mm[7] =  K7;
	EK_mm[8] =  K8;
	EK_mm[9] =  K9;
	EK_mm[10] = K10;
	EK_mm[11] = K11;
	EK_mm[12] = K12;
	EK_mm[13] = K13;
	EK_mm[14] = K14;

	// Now generate decryption keys
	uint8x16_t* DK_mm = reinterpret_cast<uint8x16_t*>(decryption_keys);
	DK_mm[0]  = K14;
	DK_mm[1]  = vaesimcq_u8(K13);
	DK_mm[2]  = vaesimcq_u8(K12);
	DK_mm[3]  = vaesimcq_u8(K11);
	DK_mm[4]  = vaesimcq_u8(K10);
	DK_mm[5]  = vaesimcq_u8(K9);
	DK_mm[6]  = vaesimcq_u8(K8);
	DK_mm[7]  = vaesimcq_u8(K7);
	DK_mm[8]  = vaesimcq_u8(K6);
	DK_mm[9]  = vaesimcq_u8(K5);
	DK_mm[10] = vaesimcq_u8(K4);
	DK_mm[11] = vaesimcq_u8(K3);
	DK_mm[12] = vaesimcq_u8(K2);
	DK_mm[13] = vaesimcq_u8(K1);
	DK_mm[14] = K0;
}

void aesni_256_key_schedule_only_encryption(const uint8_t input_key[], uint32_t encryption_keys[60])
{

	const uint8x16_t K0 = vld1q_u8(input_key);
	const uint8x16_t K1 = vld1q_u8(input_key + 16);

	const uint8x16_t K2 = aes_128_key_expansion(K0, aeskeygenassist_si8x16(K1, 0x01));
	const uint8x16_t K3 = aes_256_key_expansion(K1, K2);

	const uint8x16_t K4 = aes_128_key_expansion(K2, aeskeygenassist_si8x16(K3, 0x02));
	const uint8x16_t K5 = aes_256_key_expansion(K3, K4);

	const uint8x16_t K6 = aes_128_key_expansion(K4, aeskeygenassist_si8x16(K5, 0x04));
	const uint8x16_t K7 = aes_256_key_expansion(K5, K6);

	const uint8x16_t K8 = aes_128_key_expansion(K6, aeskeygenassist_si8x16(K7, 0x08));
	const uint8x16_t K9 = aes_256_key_expansion(K7, K8);

	const uint8x16_t K10 = aes_128_key_expansion(K8, aeskeygenassist_si8x16(K9, 0x10));
	const uint8x16_t K11 = aes_256_key_expansion(K9, K10);

	const uint8x16_t K12 = aes_128_key_expansion(K10, aeskeygenassist_si8x16(K11, 0x20));
	const uint8x16_t K13 = aes_256_key_expansion(K11, K12);

	const uint8x16_t K14 = aes_128_key_expansion(K12, aeskeygenassist_si8x16(K13, 0x40));

	uint8x16_t* EK_mm = reinterpret_cast<uint8x16_t*>(encryption_keys);
	EK_mm[0] =  K0;
	EK_mm[1] =  K1;
	EK_mm[2] =  K2;
	EK_mm[3] =  K3;
	EK_mm[4] =  K4;
	EK_mm[5] =  K5;
	EK_mm[6] =  K6;
	EK_mm[7] =  K7;
	EK_mm[8] =  K8;
	EK_mm[9] =  K9;
	EK_mm[10] = K10;
	EK_mm[11] = K11;
	EK_mm[12] = K12;
	EK_mm[13] = K13;
	EK_mm[14] = K14;
}

#undef AES_ENC_4_ROUNDS
#undef AES_ENC_4_LAST_ROUNDS
#undef AES_DEC_4_ROUNDS
#undef AES_DEC_4_LAST_ROUNDS


#endif