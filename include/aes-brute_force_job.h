#include <stdint.h>
#include <vector>
#include <cstring>
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

		std::vector<std::vector<uint8_t>> test_keys;

		uint64_t loop_cnt;

		//Character Info

		//Character Range
		uint8_t character_lookup_table[256];
		uint8_t byte_min = 0x00;
		uint8_t byte_max = 0xFF;		

		//Functions
		uint64_t search_continuous(uint8_t byte_min, uint8_t byte_max);
		uint64_t search(uint8_t byte_min, uint8_t* character_lookup_table);

		void recursive_keys(std::string bit_key_mask, unsigned int index, std::string data, std::vector<uint8_t> init_key);
		std::string toBinary(std::vector<uint8_t> in);

		//Initalization
		aes_brute_force_job(std::vector<uint8_t> key_mask, std::vector<uint8_t> key_input, std::vector<uint8_t> plain, std::vector<uint8_t> cipher);

};


