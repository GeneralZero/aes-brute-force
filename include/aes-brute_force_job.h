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

		uint64_t loop_cnt;

		//Character Info

		//Character Range
		uint8_t character_lookup_table[256];
		uint8_t byte_min = 0x00;
		uint8_t byte_max = 0xFF;		

		//Functions
		void search_continuous(uint8_t byte_min, uint8_t byte_max, uint64_t &loop_cnt);
		void search(uint8_t byte_min, uint8_t* character_lookup_table, uint64_t &loop_cnt);

		//Initalization
		aes_brute_force_job(std::vector<uint8_t> key_mask, std::vector<uint8_t> key_input, std::vector<uint8_t> plain, std::vector<uint8_t> cipher);

};


