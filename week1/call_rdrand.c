#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

int main() {

    printf("call_rdrand running\n");

    const int sleep_useconds = 100000; // default 100 ms, as suggested in manual

    while (1) {
        uint64_t rand_val;
        asm volatile("rdrand %%rax" : "=a"(rand_val));
        //proint it byte by byte to compare with the leaked bytes

        unsigned char *b = (unsigned char *)&rand_val;
        printf("0x%02x%02x%02x%02x%02x%02x%02x%02x\n", b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
        
        usleep(sleep_useconds);
    }
}