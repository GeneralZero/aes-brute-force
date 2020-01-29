#include "aes_ni_botan.h"
#include <chrono>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <thread>
#include <string>
#include <vector>
#include <algorithm>
#include <regex>
#include <assert.h>


uint8_t hex_to_int(std::string hex_string){
	std::istringstream converter(hex_string);
	unsigned int value;
	converter >> std::hex >> value;
	return value;
}

void extract_chars_from_hex( const std::string& str, std::vector<uint8_t>& result ) {

	typedef std::regex_iterator<std::string::const_iterator> re_iterator;
	typedef re_iterator::value_type re_iterated;

	std::regex re("([0-9a-fA-F]{2})");

	re_iterator rit( str.begin(), str.end(), re );
	re_iterator rend;

	std::transform( rit, rend, std::back_inserter(result), 
		[]( const re_iterated& it ){ return hex_to_int(it[1]); } );
}


bool aes_brute_force::done=false;

void preform_self_tests(){
	//Test AES128 Implimenation
	if(aes128_self_test() != 0){
		std::cerr << "ERROR: AES-NI self test failed" << std::endl;
		exit(-1);
	}

	//Test AES192 Implimenation
	if(aes192_self_test() != 0){
		std::cerr << "ERROR: AES-NI self test failed" << std::endl;
		exit(-1);
	}

	//Test AES256 Implimenation
	if(aes256_self_test() != 0){
		std::cerr << "ERROR: AES-NI self test failed" << std::endl;
		exit(-1);
	}
}

void usage(){
	std::cerr << "AES encryption key brute force search" << std::endl;
	std::cerr << "Usage 1: " << argv[0] << " <key_mask> <key_in> <plain> <cipher> [byte_min] [byte_max] [n_threads]" << std::endl;
	std::cerr << "Usage 2: " << argv[0] << " <key_mask> <key_in> <plain> <cipher> restrict <sorted list of bytes> [n_threads]" << std::endl;
	std::cerr << std::endl;
	exit(-1);
}

void set_arguments(char* argv[]){
//Convert Hexstring of the KeyMask to bytes
	extract_chars_from_hex(argv[1], aes_brute_force::key_mask);

	//Check Input
	if(aes_brute_force::key_mask.size() == 16 || aes_brute_force::key_mask.size() == 24 || aes_brute_force::key_mask.size() == 32 ){
		std::cerr << "Key Mask does not have the corret number of bytes set. " << std::endl;
		usage();
	}

	//Convert Hexstring of the Key to bytes
	extract_chars_from_hex(argv[2], aes_brute_force::key_input);

	//Check Input
	if(aes_brute_force::key_input.size() != 16 || aes_brute_force::key_input.size() != 24 || aes_brute_force::key_input.size() != 32 ){
		std::cerr << "Key does not have the corret number of bytes set. " << std::endl;
		usage();
	}


	//Convert Hexstring of the Key to bytes
	extract_chars_from_hex(argv[3], aes_brute_force::plain);

	//Check Input
	if(aes_brute_force::plain.size() != 16 ){
		std::cerr << "Plaintext is not set to 16 bytes." << std::endl;
		usage();
	}

	//Convert Hexstring of the Key to bytes
	extract_chars_from_hex(argv[4], aes_brute_force::cipher);

	//Check Input
	if(aes_brute_force::cipher.size() != 16 ){
		std::cerr << "Ciphertext is not set to 16 bytes." << std::endl;
		usage();
	}
}

uint8_t* character_lookup_table(){
	//Sort values and make sure that their is no duplicates
	uint8_t character_lookup_table[256]={0};
	unsigned int last = aes_brute_force::byte_min;

	for(uint32_t i=0;i<aes_brute_force::valid_bytes.size();i++){
		character_lookup_table[last] = aes_brute_force::valid_bytes[i];
		if(i>0) {
			assert(last < aes_brute_force::valid_bytes[i]);//check values are sorted
		}
		last = aes_brute_force::valid_bytes[i];
	}
	assert(last==aes_brute_force::byte_max);
	valid_bytes[aes_brute_force::byte_max]=aes_brute_force::byte_min;//not really used right now since we have to detect overflow anyway


	//Lets Double Check the table
	unsigned int range_check=1;
	uint8_t b = aes_brute_force::byte_min;
	while(b != aes_brute_force::byte_max){
		b=valid_bytes[b];
		range_check++;
		assert(range_check <= aes_brute_force::valid_bytes.size());
	}
	//printf("range_check %u, byte_range %u\n",range_check,byte_range);
	assert(range_check == aes_brute_force::valid_bytes.size());

	return character_lookup_table;
}

int main (int argc, char* argv[]){

	//Check to make sure that the AES implimenation works on the CPU
	preform_self_tests()

	//Check Argument count
	if( (argc<5)){
		usage()
	}

	//Set Key Data from argv
	set_arguments(argv)

	//Check Arguments for Usage of specific characters or a range
	int usage=1;

	//Debug Ouput
	std::cout << "INFO: " << n_threads << " concurrent threads supported in hardware." << std::endl << std::endl;
	std::cout << "Search parameters:" << std::endl;
	std::cout << "\tn_threads:    " << n_threads << std::endl;
	std::cout << "\tkey_mask:     " << aes_brute_force::key_mask << std::endl;
	std::cout << "\tkey_in:       " << aes_brute_force::key_in << std::endl;
	std::cout << "\tplain:        " << aes_brute_force::plain << std::endl;
	std::cout << "\tcipher:       " << aes_brute_force::cipher << std::endl;


	//If Error in getting Number of threads set to a single thread
	if(n_threads == 0) {
		n_threads=1;
	}


	if(0==strcmp("restrict",argv[5])){
		//Restrict to specific byte 

		if(argc==6){
			std::cerr << "ERROR: restrict must be followed by list of bytes" <<std::endl;
			std::cerr << "Example: restrict 00_01_02_03" <<std::endl;
			exit(-1);
		}

		usage=2;

		//Get Characters from Argument
		extract_chars_from_hex(argv[6], aes_brute_force::valid_bytes);




	}
	else{
		//Restrict to specific a byte_min and a byte_max 

		//Get Characters from ranges in Arguments
		aes_brute_force::byte_min = hex_to_int(argv[5])
		aes_brute_force::byte_max = hex_to_int(argv[6])

		//Debug Information
		printf("\tbyte_min:     0x%02X\n", aes_brute_force::byte_min);
		printf("\tbyte_max:     0x%02X\n", aes_brute_force::byte_max);
		std::cout << std::endl;

		//Calculate Valid Bytes from 
		for(uint16_t i=byte_min; i<=byte_max ;i++){
			valid_bytes.push_back(i);
		}




	}

	//Create a character looktable
	auto character_lookup_table = character_lookup_table()

	//Convert Key Arguments from Hex Strings to Bytes
	unsigned int num_of_bytes;
	

	//Get Number of Threads that can be run on the CPU
	unsigned int n_threads = std::thread::hardware_concurrency();

	//Check if threads are set
	if(argc>7){
		n_threads = std::stoi(argv[7],0,0);
	}


	unsigned int offsets[32];
	uint8_t jobs_key_mask[32];

	//Parse Masks
	unsigned int n_offsets = aes_brute_force::mask_to_offsets(key_mask, offsets);
	std::vector<uint8_t> jobs_key_mask(aes_brute_force::key_mask);
	
	if(n_offsets == 1){
		n_threads = 1;
		std::cout << "INFO: n_threads set to 1 because n_offsets=1" << std::endl;
	}


	//Setup Threads
	std::vector<std::thread *> threads(n_threads);
	std::vector<aes_brute_force *> jobs(n_threads);
	aes_brute_force::reset();

	unsigned long bit_per_byte = 1;

	while((1u<<(bit_per_byte+1u)) <= valid_bytes.size()){
		bit_per_byte++;
	}//round down

/*
	if(n_threads>1){
		
		uint32_t n_jobs=1;
		for(unsigned int i=0;i<n_offsets;i++){n_jobs*=byte_range;}
		//printf("n_jobs=%u\n",n_jobs);
		//fix jobs_key_mask bits of the key for each job
		uint8_t cnt8[16];
		memset(cnt8,byte_min,sizeof(cnt8));
		unsigned int thread_i=0;
		for(unsigned int i=0;i<n_jobs;i++){
			for(unsigned int o=0;o<n_offsets;o++){
				key_in[offsets[o]] = cnt8[o];
			}
			//printf("\t%4u ",i);println_128("job key:",key_in);
			jobs.at(thread_i)->push(key_in);
			thread_i=(thread_i+1)%n_threads;
			unsigned int b=0;
			for(b=0;b<16;b++){
				if(cnt8[b]!=byte_max) break;
			}
			for(unsigned int i=0;i<b;i++){
				cnt8[i] = byte_min;
			}
			cnt8[b] = valid_bytes[cnt8[b]];
		}
*/

	//Setup Threads
	if(n_threads > 1){
		uint32_t key_mask_width = 0;
		uint32_t key_mask;
		unsigned int n_offsets=0;

		//Split the Key Mask across the number of specified threads
		do{
			key_mask_width++;
			key_mask = 1 << key_mask_width;
		}while(key_mask < n_threads);


		//Set the Mask Information to be printed
		for(unsigned int i=0;i<(key_mask_width + bit_per_byte - 1) / bit_per_byte;i++){
			jobs_key_mask[offsets[n_offsets++]] = 0;//fix those bits at the job level.
		}

		//Print info about the Mask Information
		println_128("\tjobs_key_mask:",jobs_key_mask);

		//Start Threads for the specifc job
		for(unsigned int thread_i=0;thread_i<n_threads;thread_i++){
			switch(usage){
				case 1: 
					//Brute Force with all valid bytes
					jobs.at(thread_i) = new aes_brute_force(jobs_key_mask, plain, cipher, byte_min, byte_max);
					break;
				
				case 2: 
					//Brute Force with specifc bytes
					jobs.at(thread_i) = new aes_brute_force(jobs_key_mask, plain, cipher, byte_min, byte_max, valid_bytes, byte_range);
					break;
			}
		}


		//printf("n_offsets=%u\n",n_offsets);

		//Inrease jobs for the number of bytes in the range
		uint32_t n_jobs=1;
		for(unsigned int i=0;i<n_offsets;i++){
			n_jobs *= byte_range;
		}


		//printf("n_jobs=%u\n",n_jobs);
		//fix jobs_key_mask bits of the key for each job
		uint8_t cnt8[16];
		
		memset(cnt8,byte_min,sizeof(cnt8));
		
		unsigned int thread_i=0;
		for(unsigned int i=0;i<n_jobs;i++){
			for(unsigned int o=0;o<n_offsets;o++){
				key_in[offsets[o]] = cnt8[o];
			}
			//printf("\t%4u ",i);println_128("job key:",key_in);
			jobs.at(thread_i)->push(key_in);
			thread_i=(thread_i+1)%n_threads;
			unsigned int b=0;
			for(b=0;b<16;b++){
				if(cnt8[b]!=byte_max) break;
			}
			for(unsigned int i=0;i<b;i++){
				cnt8[i] = byte_min;
			}
			cnt8[b] = valid_bytes[cnt8[b]];
		}


	}
	else{
		std::cerr << "ERROR: Can not run less than 2 threads" <<std::endl;
		exit(-1);
	}


	//Start Bruteforce
	std::cout  << std::endl << "Launching " << n_offsets*8<< " bits search" << std::endl;

	//Start Timer
	std::chrono::steady_clock::time_point start_time = std::chrono::steady_clock::now();

	//Start Threads
	for(unsigned int index=0; index < n_threads; thread_i++){
		threads.at(index) = new std::thread(&aes_brute_force::compute, jobs.at(index));
	}


	//Check Threads for AES KEY
	uint64_t loop_cnt=1;
	int thread_found=-1;
	for(unsigned int index=0;thread_i<n_threads;thread_i++){

		//Synchronize threads 
		threads.at(thread_i)->join();
		
		//Check if Key was found
		if(jobs.at(thread_i)->found){
			thread_found = thread_i;
			memcpy(key_in,jobs.at(thread_i)->correct_key,16);

		}

		//Update Count of Attempts
		loop_cnt+=jobs.at(thread_i)->loop_cnt;
	}


	//Stop Timer
	std::chrono::steady_clock::time_point end_time = std::chrono::steady_clock::now();


	//Print Key Info
	if(thread_found != -1){
		std::cout << std::endl; << "Thread " << thread_found << " claims to have found the key" << std::endl;
		println_128("\tkey found:    ",key_in);
	} else {
		std::cout << std::endl; << "No matching key could be found" << std::endl;
	}


	

	//Get Time Diffrence
	std::chrono::duration<double> time_span = std::chrono::duration_cast<std::chrono::duration<double>>(end_time - start_time);
	uint64_t time_span_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t2-t1).count();
	uint64_t key_per_sec = loop_cnt / time_span.count();

	//Print Preformatce Statistics
	std::cout << std::endl << "Performances:" << std::endl;
	std::cout << "\t" << std::dec << loop_cnt << " AES128 operations done in " << time_span.count() << "s" << std::endl;
	std::cout << "\t" << time_span_ns / loop_cnt; << "ns per AES128 operation" <<std::endl;
	
	//Print Brute Force Count 
	if(key_per_sec>1000000){
		std::cout << "\t" << std::fixed << std::setprecision(2) << key_per_sec/1000000.0 << " million keys per second" << std::endl;
	}else{
		std::cout << "\t" << key_per_sec << " keys per second" << std::endl;
	}

	return 0;

	

	//int bit_per_byte = 0;do{bit_per_byte++;}while((1<<bit_per_byte) < byte_range);//round up
	//printf("bit_per_byte=%u\n",bit_per_byte);
	//printf("byte_range=%u\n",byte_range);
	
}
