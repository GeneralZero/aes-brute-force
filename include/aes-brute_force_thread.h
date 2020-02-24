#include <stdint.h>
#include <vector>
#include <cstring>
#include <inttypes.h>
#include <wmmintrin.h> 

class aes_brute_force_thread{
	public:
		//Flags
		bool key_found;
		bool done;
		// Is the range continuous
		static bool continuous_range;



		//Varables
		uint64_t loop_cnt;
		
		
		uint n_threads;

		unsigned int offsets[16];
		unsigned int n_offsets;
		unsigned int nbits;
		//std::vector<aes128_key_t> keys;

		uint8_t correct_key[16];
		std::vector<uint8_t> key_mask;
		std::vector<uint8_t> key_input;
		std::vector<uint8_t> plain;
		std::vector<uint8_t> cipher;

		//Character Info

		//Character Range
		uint8_t byte_min = 0x00;
		uint8_t byte_max = 0xFF;

		//Character Set
		uint8_t valid_bytes[256];
		
		//
		uint64_t byte_range;
		

		//Functions

		//Test AES Implimenations to check for aes_ni instructions
		void preform_self_tests();

		void init_debug_output();

		void search_continuous(unsigned int offsets[16], unsigned int n_offsets, uint8_t key[16], uint64_t &loop_cnt);

		void search(unsigned int offsets[16], unsigned int n_offsets, uint8_t key[16], uint8_t*valid_bytes, uint64_t byte_range, uint64_t &loop_cnt);

		void compute();

		void operator()() {
			compute();
		}

		//Initalization
		aes_brute_force_thread(std::vector<uint8_t> key_mask, std::vector<uint8_t> key_input, std::vector<uint8_t> plain, 
						std::vector<uint8_t> cipher);

};


