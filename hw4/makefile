CC=cc
CFLAGS=-I.

total: aes.c gentable.c crack.c; $(CC) aes.c gentable.c -o gentable; $(CC) crack.c aes.c -o crack
gentable: aes.c gentable.c; $(CC) aes.c gentable.c -o gentable
crack: aes.h aes.c crack.c; $(CC)  -o crack crack.c  aes.c
