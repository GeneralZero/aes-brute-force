#ifndef __AES_BRUTEFORCE_H__
#define __AES_BRUTEFORCE_H__


class aes_brute_force{
	public:
		//Varables
		uint64_t loop_cnt;
		bool key_found;
		static bool done;

		unsigned int offsets[16];
		unsigned int n_offsets;
		unsigned int nbits;
		std::vector<aes128_key_t> keys;

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
		// Is the range continuous
		bool continuous_range;

		//Functions
		static void reset(){
			done=false;
		}
		static bool key_found(){
			return done;
		}
		static void set_done(){
			done=true;
		}

		//Convert 
		static unsigned int mask_to_offsets(uint8_t key_mask[16], unsigned int offsets[16]){
			unsigned int n_offsets = 0;
			int partial_byte_idx=-1;
			for(unsigned int i=0;i<16;i++){
				if(key_mask[i]){//byte granularity
					if(key_mask[i]!=0xFF) partial_byte_idx=n_offsets;
					offsets[n_offsets++] = i;
				}
			}
			if(partial_byte_idx>-1){
				//put the partial byte at the last offset for optimal search
				uint8_t tmp = offsets[n_offsets-1];
				offsets[n_offsets-1] = offsets[partial_byte_idx];
				offsets[partial_byte_idx] = tmp;
			}
			return n_offsets;
		}

	static void search( unsigned int offsets[16],
						unsigned int n_offsets,
						uint8_t key[16],                    //I/O
						uint8_t plain[16],
						uint8_t cipher[16],
						uint8_t byte_min,
						uint8_t byte_max,
						uint64_t &loop_cnt,                //output the number of iteration actually done
						bool &found                        //output
					){
		uint8_t r[16];
		uint64_t n_loops = 1;
		uint64_t byte_range = byte_max+1;
		byte_range -= byte_min;
		n_loops = 1;
		for(unsigned int i=0;i<n_offsets;i++){
			n_loops *= byte_range;
		}
		//printf("n_loops = %lu\n",n_loops);
		found=false;
		if((0==byte_min) && (0xFF==byte_max)){
			loop_cnt=0;
			uint8_t*loop_cnt8 = (uint8_t*)&loop_cnt;
			for(unsigned int o=0;o<n_offsets;o++){
				loop_cnt8[o] = key[offsets[o]];
			}
			for(;loop_cnt<n_loops;loop_cnt++){
				uint64_t cnt=loop_cnt;
				__m128i key_schedule[11];
				for(unsigned int o=0;o<n_offsets;o++){
					key[offsets[o]] = (uint8_t)cnt;
					cnt = cnt >> 8;
				}
				aes128_load_key_enc_only(key,key_schedule);
				aes128_enc(key_schedule,plain,r);

				if(0==memcmp(r,cipher,16)){
					found=true;
					done=true;
					return;
				}
			}
		}else{
			uint8_t cnt8[16];
			memset(cnt8,byte_min,sizeof(cnt8));
			for(unsigned int o=0;o<n_offsets;o++){
				uint8_t b=key[offsets[o]];
				if(b>byte_min){
					cnt8[o] = b;
				}
			}
			for(loop_cnt=0;loop_cnt<n_loops;loop_cnt++){
				__m128i key_schedule[11];
				for(unsigned int o=0;o<n_offsets;o++){
					key[offsets[o]] = cnt8[o];
				}
				aes128_load_key_enc_only(key,key_schedule);
				aes128_enc(key_schedule,plain,r);

				if(0==memcmp(r,cipher,16)){
					found=true;
					done=true;
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

	static void search( unsigned int offsets[16],
						unsigned int n_offsets,
						uint8_t key[16],                    //I/O
						uint8_t plain[16],
						uint8_t cipher[16],
						uint8_t byte_min,
						uint8_t byte_max,
						uint8_t*valid_bytes,
						uint64_t byte_range,
						uint64_t &loop_cnt,                //output the number of iteration actually done
						bool &found                        //output
					){
		uint8_t r[16];
		uint64_t n_loops = 1;
		n_loops = 1;
		for(unsigned int i=0;i<n_offsets;i++){
			n_loops *= byte_range;
		}
		//printf("n_loops = %lu\n",n_loops);
		found=false;

		uint8_t cnt8[16];
		memset(cnt8,byte_min,sizeof(cnt8));
		for(unsigned int o=0;o<n_offsets;o++){
			uint8_t b=key[offsets[o]];
			if(b>byte_min){
				cnt8[o] = b;
			}
		}
		for(loop_cnt=0;loop_cnt<n_loops;loop_cnt++){
			__m128i key_schedule[11];
			for(unsigned int o=0;o<n_offsets;o++){
				key[offsets[o]] = cnt8[o];
			}
			aes128_load_key_enc_only(key,key_schedule);
			aes128_enc(key_schedule,plain,r);

			if(0==memcmp(r,cipher,16)){
				found=true;
				done=true;
				return;
			}
			unsigned int b=0;
			for(b=0;b<16;b++){
				if(cnt8[b]!=byte_max) break;
			}
			for(unsigned int i=0;i<b;i++){
				cnt8[i] = byte_min;
			}
			cnt8[b]=valid_bytes[cnt8[b]];
		}
	}
	void compute() {
		loop_cnt=0;
		for(auto k=keys.begin();k!=keys.end();++k){
			uint64_t cnt;
			if(continuous_range) search(offsets, n_offsets, k->bytes, plain, cipher, byte_min,byte_max,cnt,found);
			else search(offsets, n_offsets, k->bytes, plain, cipher, byte_min,byte_max,valid_bytes,byte_range,cnt,found);
			loop_cnt+=cnt;
			if(found){
				memcpy(correct_key,k->bytes,16);
				return;
			}
			if(is_done()){ //used for multithread operations
				return;
			}
		}
	}
	void operator()() {
	  compute();
	}

};


#endif
