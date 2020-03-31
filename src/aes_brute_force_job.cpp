#include "aes-brute_force_job.h"
#include <bitset>

void aes_brute_force_job::search( unsigned int offsets[16], unsigned int n_offsets, uint8_t key[16], uint8_t*valid_bytes, uint64_t byte_range, uint64_t &loop_cnt){
	uint8_t r[16];
	uint64_t n_loops = 1;
	n_loops = 1;
	for(unsigned int i = 0; i < n_offsets; i++){
		n_loops *= byte_range;
	}
	//printf("n_loops = %lu\n",n_loops);
	this->key_found=false;

	uint8_t cnt8[16];
	std::memset(cnt8, this->byte_min, sizeof(cnt8));
	for(unsigned int o = 0; o < n_offsets; o++){
		uint8_t b=key[offsets[o]];
		if(b > this->byte_min){
			cnt8[o] = b;
		}
	}
	for(loop_cnt=0;loop_cnt<n_loops;loop_cnt++){
		__m128i key_schedule[11];
		for(unsigned int o = 0; o < n_offsets; o++){
			key[offsets[o]] = cnt8[o];
		}
		aes128_load_key_enc_only(key, key_schedule);
		aes128_enc(key_schedule, this->plain, r);

		if(0==std::memcpy(r, this->cipher.data(), 16)){
			this->key_found = true;
			this->done = true;
			return;
		}
		unsigned int b=0;
		for(b=0;b<16;b++){
			if(cnt8[b] != this->byte_max) break;
		}
		for(unsigned int i=0;i<b;i++){
			cnt8[i] = this->byte_min;
		}
		cnt8[b] = valid_bytes[cnt8[b]];
	}
}

std::string aes_brute_force_job::toBinary(std::vector<uint8_t> in){
    std::string ret;

    for(unsigned int i = 0; i < in.size(); i++){
        uint8_t n = in[i];
        while(n!=0){
            if(n%2==0){
                ret = "0" + ret;
            }
            else{
                ret = "1" + ret;
            }
            n/=2;
        }
    }

    return ret;
}

void recursive_keys(std::string bit_key_mask, unsigned int index, std::string data){
    if(bit_key_mask.size() == data.size()){
        std::vector<uint8_t> new_mask;
        //Convert binstring to uint_8 vector
        for (unsigned int i = 0; i < data.size(); i+= 8)
        {
            //Convert substring to uint_8
            uint8_t byte = static_cast<uint8_t>(std::stoi(data.substr(i, i+8), nullptr, 2));
            new_mask.push_back(byte);
        }
        
        test_keys.push_back(new_mask);
    }   
    else{
        if(bit_key_mask[index] == '1'){
            recursive_keys(bit_key_mask, index + 1, data + "0");
            recursive_keys(bit_key_mask, index + 1, data + "1");
        }
        else{
            recursive_keys(bit_key_mask, index + 1, data + "0");
        }
    }
}


void aes_brute_force_job::search_continuous(uint8_t byte_min, uint8_t byte_max, uint64_t &loop_cnt){
    std::vector<uint8_t> test_cipher;
    std::vector<uint8_t> test_key;
    std::vector<std::vector<uint8_t>> test_keys;


    //Set All Values of the inital key to the byte_min where the mask is approprate
    for (unsigned int byte_index = 0; byte_index < test_key.size(); byte_index++){
        if(key_mask[byte_index] != 0x00){
            test_key[byte_index] = byte_min & key_mask[byte_index];
        }
        else{
            test_key[byte_index] = key_input[byte_index];
        }
    }

    //KeyMask to binary
    std::string bit_key_mask = toBinary(key_mask);

    //Recursive Generate possoble keys



    std::bitset<256> bitset_mask = key_mask.back();
    rec_maks_gen(0, "")

    //For each byte in key
    for (unsigned int byte_index = 0; byte_index < test_key.size(); byte_index++){

        //If Key Mask needs itterations
        if(key_mask[byte_index] != 0x00){
            //For each possoble byte
            for (size_t i = 0; i <= byte_max - byte_min; i++){
                uint8_t test = (byte_min += i) & key_mask[byte_index];
                
                //Check to see if mask ignores new bit
                if(test == test_key[byte_index]){
                    continue;
                }
                test_key[byte_index] = test;


                //Do AES opperations
                std::cout << "Testing Key: " <<  << std::endl;
            }
        }


        
    }
    
    
    

    //For bytes in Key Mask
    for (){
        


        test_keys.push_back();
    }
    
    //For each bit in key
    for (size_t i = 0; i < count; i++){
        key_mask
    }
    


    //Switch statement for Keysizes
    switch (key_input.size())
    {
    case 16:
        //128 bit key
        uint32_t* test_encryption_keys = new uint32_t[44]();
        uint32_t* test_decryption_keys = new uint32_t[44]();

        for (unsigned int loop_cnt = 0; loop_cnt < test_keys.size(); loop_cnt++){
            //Get Key Decryption Keys
            aesni_128_key_schedule(job_keys[loop_cnt], &test_encryption_keys, &test_decryption_keys)

            //Get Key Encryption Keys
            aesni_128_encrypt_n(plain, test_cipher, 1, &test_encryption_keys);

            //Test if Ciphertexts are the same
            if(test_cipher == cipher){
                correct_key = job_keys[loop_cnt];
                key_found = true;
                done = true;
                break;
            }
        }
        break;
    case 24:
        //192 bit key
        uint32_t* test_encryption_keys = new uint32_t[52]();
        uint32_t* test_decryption_keys = new uint32_t[52]();

        for (unsigned int loop_cnt = 0; loop_cnt < test_keys.size(); loop_cnt++){
            //Get Key Decryption Keys
            aesni_192_key_schedule(job_keys[loop_cnt], &test_encryption_keys, &test_decryption_keys)

            //Get Key Encryption Keys
            aesni_192_encrypt_n(plain, test_cipher, 1, &test_encryption_keys);

            //Test if Ciphertexts are the same
            if(test_cipher == cipher){
                correct_key = job_keys[loop_cnt];
                key_found = true;
                done = true;
                break;
            }
        }
        break;
    case 32:
        //256 bit key
        uint32_t* test_encryption_keys = new uint32_t[60]();
        uint32_t* test_decryption_keys = new uint32_t[60]();

        for (unsigned int loop_cnt = 0; loop_cnt < test_keys.size(); loop_cnt++){
            //Get Key Decryption Keys
            aesni_256_key_schedule(job_keys[loop_cnt], &test_encryption_keys, &test_decryption_keys)

            //Get Key Encryption Keys
            aesni_256_encrypt_n(plain, test_cipher, 1, &test_encryption_keys);

            //Test if Ciphertexts are the same
            if(test_cipher == cipher){
                correct_key = job_keys[loop_cnt];
                key_found = true;
                done = true;
                break;
            }
        }
        break;

    default:
        //Error Invalid Keysize
        break;
    }

    done = true;
    





	uint8_t r[16];
	uint64_t n_loops = 1;
	uint64_t byte_range = byte_max+1;
	byte_range -= byte_min;
	n_loops = 1;
	for(unsigned int i=0; i < n_offsets; i++){
		n_loops *= byte_range;
	}
	//printf("n_loops = %lu\n",n_loops);
	this->key_found = false;
	if((this->byte_min == 0x00) && (this->byte_max == 0xFF)){
		loop_cnt=0;
		uint8_t*loop_cnt8 = (uint8_t*)&loop_cnt;
		for(unsigned int o=0;o<n_offsets;o++){
			loop_cnt8[o] = key[offsets[o]];
		}
		for(; loop_cnt < n_loops; loop_cnt++){
			uint64_t cnt = loop_cnt;
			__m128i key_schedule[11];
			for(unsigned int o = 0; o < n_offsets; o++){
				key[offsets[o]] = (uint8_t)cnt;
				cnt = cnt >> 8;
			}
			aes128_load_key_enc_only(key, key_schedule);
			aes128_enc(key_schedule, this->plain, r);

			if(0==std::memcpy(r, this->cipher.data(), 16)){
				this->key_found=true;
				this->done=true;
				return;
			}
		}
	}else{
		uint8_t cnt8[16];


		std::memset(cnt8, this->byte_min, sizeof(cnt8));

		for(unsigned int o = 0; o < n_offsets; o++){
			uint8_t b = key[offsets[o]];
			if(b > this->byte_min){
				cnt8[o] = b;
			}
		}
		for(loop_cnt = 0; loop_cnt < n_loops; loop_cnt++){
			__m128i key_schedule[11];
			for(unsigned int o=0; o < n_offsets; o++){
				key[offsets[o]] = cnt8[o];
			}
			aes128_load_key_enc_only(key, this->key_schedule);
			aes128_enc(this->key_schedule, this->plain, r);

			if(0==std::memcpy(r, this->cipher.data(), 16)){
				this->key_found=true;
				this->done=true;
				return;
			}
			unsigned int b=0;
			for(b=0;b<16;b++){
				if(cnt8[b]!=byte_max) break;
			}
			for(unsigned int i=0;i<b;i++){
				cnt8[i] = byte_min;
			}
			cnt8[b]++;
		}
	}
}