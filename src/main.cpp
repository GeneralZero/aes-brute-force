#include "aes_brute_force.h"
#include <chrono>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <thread>
#include <string>
#include <algorithm>
#include <regex>
#include <assert.h>

//Create AES Brute Force Object with key inputs and number of threds
	//Run AES NI tests
	//Parse Argv inputs and print info
	//

//Set Character List with setting up thread objects
	//Set up character list object
	//Check Character list object
	//Set Up subkeys from Keymask
	//

//Run threads

//Wait for termination

//Print output


//Print Bytes in hex
int print_bytes(std::vector<uint8_t>& key){
	uint i = 0;
	for (; i < key.size(); ++i){
		if(i != 0 && i % 8 == 0){
			std::cout << "_";
		}
		printf("%02X", key.at(i));
	}
	std::cout << std::endl;

	return i;
}

//Convert Single Hex to uint8_t
uint8_t hex_to_int(std::string hex_string){
	std::istringstream converter(hex_string);
	unsigned int value;
	converter >> std::hex >> value;
	return value;
}

//Convert HexString to Vector<uint8_t>
void extract_chars_from_hex(const std::string& str, std::vector<uint8_t>& result) {
	typedef std::regex_iterator<std::string::const_iterator> re_iterator;
	typedef re_iterator::value_type re_iterated;

	std::regex re("([0-9a-fA-F]{2})");

	re_iterator rit( str.begin(), str.end(), re );
	re_iterator rend;

	std::transform( rit, rend, std::back_inserter(result), 
		[]( const re_iterated& it ){ return hex_to_int(it[1]); } );
}


//Print Usage and Exit
void usage(char* program_name){
	std::cerr << "AES encryption key brute force search" << std::endl;
	std::cerr << "Usage 1: " << program_name << " <key_mask> <key_in> <plain> <cipher> [byte_min] [byte_max] [n_threads]" << std::endl;
	std::cerr << "Usage 2: " << program_name << " <key_mask> <key_in> <plain> <cipher> restrict <sorted list of bytes> [n_threads]" << std::endl;
	std::cerr << std::endl;
	exit(-1);
}

//Convert Hexstring of the KeyMask to bytes
void set_arguments(char* argv[]){

}

//Get Number of Threads that can be run on the CPU
unsigned int get_thread_count(unsigned int n){
	unsigned int n_threads = std::thread::hardware_concurrency();

	//If Error in getting Number of threads set to a single thread
	if (n != 0){
		if (n_threads == 0){
			std::cout << "Could not automaticly get number of CPUs. Setting threads to " << n << std::endl;
		}
		else{
			std::cout << "Manually setting threads to cli input." << std::endl;
		}
		
		return n;
	}

	return n_threads;
}

int main (int argc, char* argv[]){
	unsigned int n_threads;
	std::vector<uint8_t> key_mask;
	std::vector<uint8_t> key_input;
	std::vector<uint8_t> plain;
	std::vector<uint8_t> cipher;
	std::vector<uint8_t> valid_bytes;

	//Check Argument count
	if( (argc<5)){
		usage(argv[0]);
	}


	//Check if threads are set
	if(argc>7){
		n_threads = get_thread_count(std::stoi(argv[7],0,0));
	}
	else{
		n_threads = get_thread_count(0);
	}

	extract_chars_from_hex(argv[1], key_mask);

	//Check Input
	if(key_mask.size() == 16 || key_mask.size() == 24 || key_mask.size() == 32 ){
		std::cerr << "Key Mask does not have the corret number of bytes set. " << std::endl;
		usage(argv[0]);
	}

	//Convert Hexstring of the Key to bytes
	extract_chars_from_hex(argv[2], key_input);

	//Check Input
	if(key_input.size() != 16 || key_input.size() != 24 || key_input.size() != 32 ){
		std::cerr << "Key does not have the corret number of bytes set. " << std::endl;
		usage(argv[0]);
	}


	//Convert Hexstring of the Key to bytes
	extract_chars_from_hex(argv[3], plain);

	//Check Input
	if(plain.size() != 16 ){
		std::cerr << "Plaintext is not set to 16 bytes." << std::endl;
		usage(argv[0]);
	}

	//Convert Hexstring of the Key to bytes
	extract_chars_from_hex(argv[4], cipher);

	//Check Input
	if(cipher.size() != 16 ){
		std::cerr << "Ciphertext is not set to 16 bytes." << std::endl;
		usage(argv[0]);
	}

	//Get Number of Threads that can be run on the CPU
	auto bruteforcer = new aes_brute_force(key_mask, key_input, plain, cipher);

	bruteforcer->init_debug_output();

	//Check to make sure that the AES implimenation works on the CPU
	bruteforcer->preform_self_tests();

	if(strcmp("restrict", argv[5]) == 0){
		//Restrict the range of characters to specific character set

		if(argc==6){
			std::cerr << "ERROR: restrict must be followed by list of bytes" <<std::endl;
			std::cerr << "Example: restrict 00_01_02_03" <<std::endl;
			exit(-1);
		}

		//Get Characters from Argument for specific byte range
		extract_chars_from_hex(argv[6], valid_bytes);

		//Set the character range for 
		bruteforcer->set_character_range(valid_bytes);

	}
	else{
		//Restrict to specific a byte_min and a byte_max 

		if (argc >= 7){
			//Get Characters from ranges in Arguments
			bruteforcer->set_character_range(hex_to_int(argv[5]), hex_to_int(argv[6]));
		}
		else{
			bruteforcer->set_character_range(0x00, 0xFF);	
		}

		//Debug Information
		printf("\tbyte_min:     0x%02X\n", bruteforcer->byte_min);
		printf("\tbyte_max:     0x%02X\n", bruteforcer->byte_max);
		std::cout << std::endl;
	}

	//Setup Threads and key jobs
	bruteforcer->setup_threads(n_threads);

	//Log number of bits to Bruteforce
	std::cout  << std::endl << "Launching " << bruteforcer->number_of_bits_to_find << " bits search" << std::endl;

	//Start Timer
	std::chrono::steady_clock::time_point start_time = std::chrono::steady_clock::now();

	//Start Threads
	bruteforcer->start_threads();

	


	//Check Threads for AES KEY
	uint64_t loop_cnt=1;
	int thread_found=-1;
	for(unsigned int thread_index=0; thread_index < n_threads; thread_index++){

		//Synchronize threads 
		threads.at(thread_index)->join();
		
		//Check if Key was found
		if(jobs.at(thread_index)->key_found){
			thread_found = thread_index;
			auto winning_thread = jobs.at(thread_index);
			std::memcpy(aes_brute_force::key_input, winning_thread->correct_key, winning_thread->correct_key.size());
		}

		//Update Count of Attempts
		loop_cnt+=jobs.at(thread_index)->loop_cnt;
	}

	//Stop Timer
	std::chrono::steady_clock::time_point end_time = std::chrono::steady_clock::now();

	//Print Key Info
	if(thread_found != -1){
		std::cout << std::endl << "Thread " << thread_found << " claims to have found the key" << std::endl;
		std::cout << "\tkey found:    ";
		print_bytes(aes_brute_force::key_input);
	} else {
		std::cout << std::endl << "No matching key could be found" << std::endl;
	}	

	//Get Time Diffrence
	std::chrono::duration<double> time_span = std::chrono::duration_cast<std::chrono::duration<double>>(end_time - start_time);
	uint64_t time_span_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();
	uint64_t key_per_sec = loop_cnt / time_span.count();

	//Print Preformatce Statistics
	std::cout << std::endl << "Performances:" << std::endl;
	std::cout << "\t" << std::dec << loop_cnt << " AES128 operations done in " << time_span.count() << "s" << std::endl;
	std::cout << "\t" << time_span_ns / loop_cnt << "ns per AES128 operation" <<std::endl;
	
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
