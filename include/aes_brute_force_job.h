#ifndef AES_BRUTE_FORCE_JOB
#define AES_BRUTE_FORCE_JOB 

#include <stdint.h>
#include <vector>
#include <string>
#include <cstring>
#include <iostream>
#include <inttypes.h>

class aes_brute_force_job{
    public:
        //Flags
        bool key_found;
        bool done;

        //Varables
        std::vector<uint8_t> correct_key;
        std::vector<uint8_t> key_mask;
        std::vector<uint8_t> key_input;
        uint8_t* plain;
        uint8_t* cipher;

        uint64_t loop_cnt;

        //Character Info
        std::vector<uint8_t> non_zero_indexes;
        uint8_t non_zero_index_length;

        //Character Range
        uint8_t* valid_characters;
        uint8_t character_lookup_count;
        uint8_t byte_min = 0x00;
        uint8_t byte_max = 0xFF;

        //Encryption Varables
        uint32_t* test_encryption_key;
        uint32_t* test_decryption_key;
        uint8_t* test_cipher;

        //Functions
        uint64_t search_continuous(uint8_t byte_min, uint8_t byte_max);
        uint64_t search(std::vector<uint8_t> valid_bytes);

        //Recursive Search
        void search_recursion_continious(std::vector<uint8_t> test_key, uint8_t index);
        void search_recursion_list(std::vector<uint8_t> test_key, uint8_t index);

        //Initalization
        aes_brute_force_job(std::vector<uint8_t> key_mask, std::vector<uint8_t> key_input, std::vector<uint8_t> plain, std::vector<uint8_t> cipher);

};


#endif
