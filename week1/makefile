CC=gcc
CFLAGS=-O3 -Wall -pthread -march=native

all: clean call_rdrand crosstalk

clean:
	rm -f call_rdrand crosstalk

call_rdrand: call_rdrand.c
	$(CC) $(CFLAGS) -o call_rdrand call_rdrand.c

crosstalk: crosstalk.c asm.h
	$(CC) $(CFLAGS) -o crosstalk crosstalk.c
