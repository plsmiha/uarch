CC=gcc
CFLAGS=-O3 -Wall -pthread -march=native

all: clean attack hash

clean:
	rm -f attack hash

attack: attack.c asm.h
	$(CC) $(CFLAGS) -o attack attack.c

hash: hash.c asm.h
	$(CC) $(CFLAGS) -o hash hash.c