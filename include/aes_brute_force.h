#include <stdint.h>
#include <vector>
#include <cstring>
#include <inttypes.h>
#include <wmmintrin.h> 
#include <future>

#include "aes_brute_force_job.h"

void print_bytes(std::vector<uint8_t> key);

class aes_brute_force{
    public:
        //Flags
        bool key_found;
        bool done;
        // Is the range continuous
        bool continuous_range;

        //Mask Information
        std::vector<unsigned int> mask_indexes;
        std::vector<uint8_t> jobs_key_mask;
        unsigned int number_of_bits_to_find = 0;

        //Debug Information
        uint64_t loop_cnt;

        //Input and Output AES information
        uint8_t correct_key[16];
        std::vector<uint8_t> key_mask;
        std::vector<uint8_t> key_input;
        std::vector<uint8_t> plain;
        std::vector<uint8_t> cipher;


        //Character Range
        uint8_t byte_min = 0x00;
        uint8_t byte_max = 0xFF;
        uint8_t number_of_characters = 0;

        //Character Set
        std::vector<uint8_t> valid_bytes;
        uint8_t character_lookup_table[256];
        

        //Threads and jobs
        unsigned int n_threads;
        std::vector<std::future<uint64_t>> threads;
        std::vector<aes_brute_force_job *> jobs;

        //Run Threads Functions
        void start_threads();
        void search_continuous(unsigned int offsets[16], unsigned int n_offsets, uint8_t key[16], uint64_t &loop_cnt);

        void search(unsigned int offsets[16], unsigned int n_offsets, uint8_t key[16], uint8_t*valid_bytes, uint64_t byte_range, uint64_t &loop_cnt);

        void compute();

        void operator()() {
            compute();
        }

        //Debug Information
        void init_debug_output();

        //Test AES Implimenations to check for aes_ni instructions
        void preform_self_tests();
        bool aes128_self_test();
        bool aes192_self_test();
        bool aes256_self_test();

        //Setup Functions
        void set_character_range(std::vector<uint8_t> valid_bytes);
        void set_character_range(uint8_t min_byte, uint8_t max_byte);
        unsigned int mask_to_offsets();
        void setup_threads(unsigned int n_threads);

        //Initalization
        aes_brute_force(std::vector<uint8_t> key_mask, std::vector<uint8_t> key_input, std::vector<uint8_t> plain, 
                        std::vector<uint8_t> cipher);

};


