CC=gcc
CFLAGS=-O3 -Wall -pthread -march=native

all: clean attack

clean:
	rm -f attack

attack: attack.c asm.h
	$(CC) $(CFLAGS) -o attack attack.c
