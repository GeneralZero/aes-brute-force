#ifndef AES_BRUTE_FORCE_JOB
#define AES_BRUTE_FORCE_JOB 

#include <stdint.h>
#include <vector>
#include <string>
#include <cstring>
#include <iostream>
#include <inttypes.h>
#include <wmmintrin.h> 

class aes_brute_force_job{
	public:
		//Flags
		bool key_found;
		bool done;

		//Varables
		std::vector<uint8_t> correct_key;
		std::vector<uint8_t> key_mask;
		std::vector<uint8_t> key_input;
		std::vector<uint8_t> plain;
		std::vector<uint8_t> cipher;

		uint64_t loop_cnt;

		//Character Info
		std::vector<uint8_t> non_zero_indexes;

		//Character Range
		uint8_t character_lookup_table[256];
		uint8_t byte_min = 0x00;
		uint8_t byte_max = 0xFF;		

		//Functions
		uint64_t search_continuous(uint8_t byte_min, uint8_t byte_max);
		uint64_t search(uint8_t byte_min, uint8_t* character_lookup_table);

		//Recursive Search
		void search_recursion_continious(std::vector<uint8_t> test_key, uint8_t index, std::vector<uint8_t> non_zero_indexes);

		//Initalization
		aes_brute_force_job(std::vector<uint8_t> key_mask, std::vector<uint8_t> key_input, std::vector<uint8_t> plain, std::vector<uint8_t> cipher);

};


#endif
