CC=gcc
CFLAGS=-O3 -Wall -mrdrnd -fno-strict-aliasing 

all: fpvi

fpvi: fpvi.c asm.h
	$(CC) $(CFLAGS) -o fpvi fpvi.c

clean:
	rm -f fpvi

run: fpvi
	./fpvi