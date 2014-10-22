CC=cc
CFLAGS=-std=c99 -w -o

total: aes.c gentable.c crack.c; $(CC) aes.c gentable.c $(CFLAGS) gentable; $(CC) crack.c aes.c  $(CFLAGS) crack
gentable: aes.c gentable.c; $(CC) aes.c gentable.c  -o gentable
crack: aes.h aes.c crack.c; $(CC)   -o crack crack.c  aes.c
