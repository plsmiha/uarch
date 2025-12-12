CC=gcc
CFLAGS=-O3 -Wall -pthread -march=native

all: clean attack leak_hash

clean:
	rm -f attack leak_hash

attack: attack.c asm.h
	$(CC) $(CFLAGS) -o attack attack.c

leak_hash: leak_hash.c
	gcc leak_hash.c -Os -Wall -o leak_hash -mrtm
