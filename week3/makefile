CC=gcc
CFLAGS=-O3 -Wall -pthread -march=native

all: clean crosstalk

clean:
	rm -f crosstalk

crosstalk: crosstalk.c asm.h
	$(CC) $(CFLAGS) -o crosstalk crosstalk.c
