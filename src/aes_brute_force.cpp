#include "aes_brute_force.h"
#include "aes_brute_force_job.h"
#include "aes_ni_botan.h"
#include <iostream>
#include <assert.h>
#include <bitset>
#include <algorithm>
#include <future>

//Functions
//Print Bytes in hex
void print_bytes(std::vector<uint8_t> key){
	unsigned int i = 0;
	for (; i < key.size(); ++i){
		if(i != 0 && i % 8 == 0){
			std::cout << "_";
		}
		printf("%02X", key.at(i));
	}
	std::cout << std::endl;
}

void aes_brute_force::init_debug_output(){
	//Debug Ouput
	//std::cout << "INFO: " << n_threads << " concurrent threads supported in hardware." << std::endl << std::endl;
	std::cout << "Search parameters:" << std::endl;
	std::cout << "\tn_threads:    " << this->n_threads << std::endl;
	std::cout << "\tkey_mask:     "; print_bytes(key_mask);
	std::cout << "\tkey_in:       "; print_bytes(key_input);
	std::cout << "\tplain:        "; print_bytes(plain);
	std::cout << "\tcipher:       "; print_bytes(cipher);
	printf("\tbyte_min:     0x%02X\n", this->byte_min);
	printf("\tbyte_max:     0x%02X\n", this->byte_max);
}

void aes_brute_force::setup_threads(unsigned int threads_count){
	this->n_threads = threads_count; 

	//Search for the largest bit and set tne number of bits to search through
	auto largest_byte_idx = mask_to_offsets();

	auto replace_key_byte = key_mask.at(largest_byte_idx);

	if(number_of_bits_to_find <= 1){
		this->n_threads = 1;
		std::cout << "INFO: n_threads set to 1 because num_brute_mask_bytes=1" << std::endl;
	}

	//Set the number of threads
	threads.resize(this->n_threads);
	//jobs.resize(this->n_threads);

	//Generate Job Mask
	std::vector<uint8_t> job_mask(key_mask);
	//Set the largest_byte_idx to Zero
	job_mask[largest_byte_idx] = 0x00;

	//Print info about the Mask Information
	//printf("\tjobs_key_mask: ");
	//print_bytes(jobs_key_mask);

	//Generate Keys for Jobs
	std::vector<std::vector<uint8_t>> job_keys;

	if (continuous_range){
		//Generate Job Keys Baised on Character start for a continious range
		for (size_t i = 0; i < number_of_characters; i++){
			//Generate the key from the input key and the keymask with the specific character as the unique key
			std::vector<uint8_t> temp{key_input};
			temp.at(largest_byte_idx) = (byte_min + i) & replace_key_byte;
			job_keys.push_back(temp);
		}
	}
	else{
		//Generate Job Keys Baised on Character start for a non continious range
		auto key_start = character_lookup_table[byte_min];
		while (key_start != byte_max) {
			auto temp = jobs_key_mask;
			temp.at(largest_byte_idx) = (key_start) & replace_key_byte;
			job_keys.push_back(temp);
			
			key_start = character_lookup_table[key_start];
		} 
	}

	//Remove Duplicate Job Keys. This can happen when the the mask is a partial mask
	std::sort(job_keys.begin(), job_keys.end());
	job_keys.erase(std::unique( job_keys.begin(), job_keys.end()), job_keys.end());

	//Use job keys to generate jobs for the specific number of threads
	for (unsigned int job_index = 0; job_index < job_keys.size(); job_index++){
		jobs.push_back(new aes_brute_force_job(job_mask, job_keys[job_index], plain, cipher));
	}

	// Each Job will use the job mask and set the min byte for the keys
	// Then it will loop use the character_lookup_table or increasing byte count

}

void aes_brute_force::start_threads(){
	for(unsigned int job_index=0; job_index < jobs.size(); job_index++){
		if(continuous_range){
			threads[job_index % n_threads] = std::async(std::launch::async, &aes_brute_force_job::search_continuous, jobs.at(job_index), byte_min, byte_max);
		}
		else{
			threads[job_index % n_threads] = std::async(std::launch::async, &aes_brute_force_job::search, jobs.at(job_index), byte_min, character_lookup_table);
		}
		
	}
}

//Convert Key Mask to the number of bits and the location of them
unsigned int aes_brute_force::mask_to_offsets(){
	int largest_byte_idx=-1;
	uint largest_byte=0;

	for(unsigned int i=0; i < key_mask.size(); i++){
		//Skip Byte if 00
		if(key_mask[i] == 0x00){
			continue;
		}
		else{
			if(key_mask[i] == 0xFF) {
				largest_byte = 16;
				largest_byte_idx = i;
				number_of_bits_to_find += 8;
			}
			else{
				unsigned int bits_set = std::bitset<8>(key_mask[i]).count();
				if(largest_byte < bits_set){
					largest_byte_idx = i;
				}
				number_of_bits_to_find += bits_set;
			}

			mask_indexes.push_back(i);
		}
	}

	return largest_byte_idx;
}

void aes_brute_force::set_character_range(std::vector<uint8_t> valid_bytes){
	//Sort values and make sure that their is no duplicates
	unsigned int last = byte_min;
	number_of_characters = valid_bytes.size();

	for(uint32_t i=0; i < number_of_characters; i++){
		character_lookup_table[last] = valid_bytes.at(i);
		if(i>0) {
			assert(last < valid_bytes.at(i));//check values are sorted
		}
		last = valid_bytes.at(i);
	}
	character_lookup_table[byte_max] = byte_min;

	//Lets Double Check the table
	unsigned int range_check=1;
	uint8_t byte = byte_min;
	while(byte != byte_max){
		byte = valid_bytes[byte];
		range_check++;
		assert(range_check <= 255);
	}
	//printf("range_check %u, byte_range %u\n", range_check, byte_range);
	assert(range_check == number_of_characters);
}

void aes_brute_force::set_character_range(uint8_t min_byte, uint8_t max_byte){
	//Sort values and make sure that their is no duplicates

	this->byte_min = min_byte;
	this->byte_max = max_byte;

	this->number_of_characters = max_byte - min_byte;

	this->continuous_range = true;
}


//AES Testing

//Test AES Implimenations to check for aes_ni instructions
void aes_brute_force::preform_self_tests(){
	//Test AES128 Implimenation
	if(aes128_self_test() != true){
		std::cerr << "ERROR: AES-NI 128 self test failed" << std::endl;
		exit(-1);
	}

	//Test AES192 Implimenation
	if(aes192_self_test() != true){
		std::cerr << "ERROR: AES-NI 192 self test failed" << std::endl;
		exit(-1);
	}

	//Test AES256 Implimenation
	if(aes256_self_test() != true){
		std::cerr << "ERROR: AES-NI 256 self test failed" << std::endl;
		exit(-1);
	}
}

bool aes_brute_force::aes128_self_test(){
	//AES-128
	const uint8_t plain[]      = {0x86, 0x47, 0x66, 0xd7, 0x8c, 0xb, 0xee, 0xbe, 0x29, 0x9a, 0x41, 0xee, 0xc5, 0x80, 0x94, 0x22};
	const uint8_t enc_key[]    = {0xc2, 0x63, 0x97, 0xf1, 0xf4, 0x5b, 0x19, 0x6a, 0x8a, 0xf, 0xd9, 0xab, 0xcc, 0xad, 0x57, 0x1};
	const uint8_t cipher[]     = {0xb8, 0xdd, 0xb2, 0x3f, 0x98, 0x56, 0xa3, 0x15, 0x8e, 0x65, 0xb3, 0x3, 0x21, 0xe1, 0x1e, 0x64};

	auto computed_cipher = new uint8_t[16];
	auto computed_plain  = new uint8_t[16];
	auto encryption_key_schedule = new uint32_t[44];
	auto decryption_key_schedule = new uint32_t[44];
	
	//Do encryption and decryption to make sure AESNI is working
	aesni_128_key_schedule(enc_key, encryption_key_schedule, decryption_key_schedule);
	aesni_128_encrypt_n(plain,  computed_cipher, 1, encryption_key_schedule);
	aesni_128_decrypt_n(cipher, computed_plain,  1, encryption_key_schedule);

	//Check both cipher and plaintext
	return memcmp(cipher, computed_cipher, sizeof(cipher)) || memcmp(plain, computed_plain, sizeof(plain));
}


bool aes_brute_force::aes192_self_test(){
	//AES-192
	const uint8_t plain[]      = {0x86, 0x47, 0x66, 0xd7, 0x8c, 0xb, 0xee, 0xbe, 0x29, 0x9a, 0x41, 0xee, 0xc5, 0x80, 0x94, 0x22};
	const uint8_t enc_key[]    = {0xa, 0xb1, 0x56, 0xd0, 0x73, 0xb6, 0x60, 0xaa, 0xf2, 0xd6, 0xf4, 0x8, 0x55, 0x93, 0x54, 0xb3, 0x1, 0x9c, 0x56, 0x5c, 0x54, 0x6, 0xe0, 0x4a};
	const uint8_t cipher[]     = {0x79, 0xb3, 0x3f, 0x19, 0xdf, 0xcd, 0x87, 0x79, 0x37, 0x53, 0xf8, 0xbe, 0x1f, 0x6a, 0xb5, 0x32};

	auto computed_cipher = new uint8_t[16];
	auto computed_plain  = new uint8_t[16];
	auto encryption_key_schedule = new uint32_t[52];
	auto decryption_key_schedule = new uint32_t[52];
	
	//Do encryption and decryption to make sure AESNI is working
	aesni_192_key_schedule(enc_key, encryption_key_schedule, decryption_key_schedule);
	aesni_192_encrypt_n(plain,  computed_cipher, 1, encryption_key_schedule);
	aesni_192_decrypt_n(cipher, computed_plain, 1,  encryption_key_schedule);

	//Check both cipher and plaintext
	return memcmp(cipher, computed_cipher, sizeof(cipher)) || memcmp(plain, computed_plain, sizeof(plain));
}


bool aes_brute_force::aes256_self_test(){
	//AES-256
	const uint8_t plain[]      = {0x86, 0x47, 0x66, 0xd7, 0x8c, 0xb, 0xee, 0xbe, 0x29, 0x9a, 0x41, 0xee, 0xc5, 0x80, 0x94, 0x22};
	const uint8_t enc_key[]    = {0x58, 0xb2, 0xae, 0x22, 0xe9, 0x11, 0x10, 0x2c, 0x91, 0xa9, 0xb8, 0x3d, 0xd8, 0xaf, 0x23, 0x5b, 0x78, 0xe9, 0xba, 0x1b, 0x4, 0x41, 0x81, 0x77, 0xdf, 0xad, 0xdb, 0xd3, 0x69, 0x92, 0xc2, 0x38};
	const uint8_t cipher[]     = {0xdd, 0xcc, 0x1c, 0xbf, 0x22, 0x61, 0x56, 0x1, 0x8d, 0xbe, 0x65, 0x85, 0xb0, 0xd8, 0x4d, 0x88};	

	auto computed_cipher = new uint8_t[16];
	auto computed_plain  = new uint8_t[16];
	auto encryption_key_schedule = new uint32_t[60];
	auto decryption_key_schedule = new uint32_t[60];
	
	//Do encryption and decryption to make sure AESNI is working
	aesni_256_key_schedule(enc_key, encryption_key_schedule, decryption_key_schedule);
	aesni_256_encrypt_n(plain,  computed_cipher, 1, encryption_key_schedule);
	aesni_256_decrypt_n(cipher, computed_plain, 1,  encryption_key_schedule);

	//Check both cipher and plaintext
	return memcmp(cipher, computed_cipher, sizeof(cipher)) || memcmp(plain, computed_plain, sizeof(plain));
}

//Initalization
aes_brute_force::aes_brute_force(std::vector<uint8_t> key_mask, std::vector<uint8_t> key_input, std::vector<uint8_t> plain, 
				std::vector<uint8_t> cipher){
	this->done = false;
	this->key_found = false;
	this->loop_cnt = 0;

	this->byte_min = 0x00;
	this->byte_max = 0xFF;

	this->key_mask = std::vector<uint8_t>(key_mask);
	this->key_input = std::vector<uint8_t>(key_input);
	
	//Set key_input
	for (uint i = 0; i < key_input.size(); i++)
	{
		this->key_input[i] &= ~key_mask[i];
	}
	
	this->plain = std::vector<uint8_t>(plain);
	this->cipher = std::vector<uint8_t>(cipher);

	std::cout << "Starting Self Tests" << std::endl;
	preform_self_tests();

	//
	//std::cout << "Printing Debug Information";
	//init_debug_output();
}

