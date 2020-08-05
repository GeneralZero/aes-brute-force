#include "aes_brute_force_job.h"
#include "aes_ni_botan.h"
#include <bitset>


//Initalization
aes_brute_force_job::aes_brute_force_job(std::vector<uint8_t> key_mask, std::vector<uint8_t> key_input, std::vector<uint8_t> plain, 
                std::vector<uint8_t> cipher){
    this->done = false;
    this->key_found = false;
    this->loop_cnt = 0;

    this->correct_key = std::vector<uint8_t>();
    this->key_mask = std::vector<uint8_t>(key_mask);
    this->key_input = std::vector<uint8_t>(key_input);
    this->plain = std::vector<uint8_t>(plain);
    this->cipher = std::vector<uint8_t>(cipher);

    this->test_cipher = new uint8_t[16];

    if (this->key_input.size() == 16)
    {
        //128 bit key
        test_encryption_key = new uint32_t[44]();
        test_decryption_key = new uint32_t[44]();
    }
    else if (this->key_input.size() == 24){
        //192 bit key
        test_encryption_key = new uint32_t[52]();
        test_decryption_key = new uint32_t[52]();
    }
    else if(this->key_input.size() == 32){
        //256 bit key
        test_encryption_key = new uint32_t[60]();
        test_decryption_key = new uint32_t[60]();
    }
    else{

    }
    

}


uint64_t aes_brute_force_job::search_continuous(uint8_t byte_min, uint8_t byte_max){
    std::vector<uint8_t> test_key(key_input);

    //Set varables
    this->byte_max = byte_max;
    this->byte_min = byte_min;

    //Set All Values of the inital key to the byte_min where the mask is approprate
    for (unsigned int byte_index = 0; byte_index < test_key.size(); byte_index++){
        if(key_mask[byte_index] != 0x00){
            test_key[byte_index] = byte_min & key_mask[byte_index];
            non_zero_indexes.push_back(byte_index);
        }
    }

    //Test with Recurstion
    search_recursion_continious(test_key, 0, non_zero_indexes);

    done = true;
    
    return loop_cnt;
}


uint64_t aes_brute_force_job::search(uint8_t byte_min, uint8_t* character_lookup_table){
    std::vector<uint8_t> test_key;

    //Set All Values of the inital key to the byte_min where the mask is approprate
    for (unsigned int byte_index = 0; byte_index < test_key.size(); byte_index++){
        if(key_mask[byte_index] != 0x00){
            test_key[byte_index] = byte_min & key_mask[byte_index];
        }
        else{
            test_key[byte_index] = key_input[byte_index];
        }
    }

    done = true;
    
    return loop_cnt;
}


void aes_brute_force_job::search_recursion_continious(std::vector<uint8_t> test_key, uint8_t index, std::vector<uint8_t> non_zero_indexes){

    if (index == non_zero_indexes.size() -1){

        //Loop over the last index In range of byte_min - byte_max
        for (size_t j = byte_min; j <= byte_max; j++)
        {
            //Change the last index
            test_key[non_zero_indexes[index]] = j & key_mask[non_zero_indexes[index]];
            //std::cout << test_key.data() << std::endl;

            //Update loop count
            loop_cnt++;

            //Test Encryption
            //Switch statement for Keysizes
            switch (test_key.size()){
                case 16:
                {
                    //Get Key Decryption Keys
                    aesni_128_key_schedule(const_cast<const uint8_t*>(test_key.data()), test_encryption_key, test_decryption_key);

                    //Get Key Encryption Keys
                    aesni_128_encrypt_n(plain.data(), test_cipher, 1, test_encryption_key);

                    break;
                }
                case 24:
                {
                    //Get Key Decryption Keys
                    aesni_192_key_schedule(const_cast<const uint8_t*>(test_key.data()), test_encryption_key, test_decryption_key);

                    //Get Key Encryption Keys
                    aesni_192_encrypt_n(plain.data(), test_cipher, 1, test_encryption_key);

                    break;
                }
                case 32:
                {
                    //Get Key Decryption Keys
                    aesni_256_key_schedule(const_cast<const uint8_t*>(test_key.data()), test_encryption_key, test_decryption_key);

                    //Get Key Encryption Keys
                    aesni_256_encrypt_n(plain.data(), test_cipher, 1, test_encryption_key);

                    break;
                }
                default:
                    //Error Invalid Keysize
                    break;

            }
            
            //Test if Ciphertexts are the same
            if(memcmp(test_cipher, cipher.data(), cipher.size()) == 0){
                copy(test_key.begin(), test_key.end(), back_inserter(correct_key)); 
                key_found = true;
                done = true;
                break;
            }
        }

    }
    else{
        for (size_t j = byte_min; j <= byte_max; j++){
            //Set New test Key
            auto new_test_key = std::vector<uint8_t>(test_key);
            test_key[non_zero_indexes[index]] = j & key_mask[non_zero_indexes[index]];

            //Update index and 
            search_recursion_continious(test_key, index +1, non_zero_indexes);
        }
    }
}

