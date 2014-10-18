#include "stdio.h"
#include "stdlib.h"
#include "aes.h"

void print_chars (
	char *chars, 
	int len
	);
/*
 *  assign -- transform long long (64 bit unsigned integer) val to 16 byte array pass
 */

void assign (
	unsigned char *pass, 
	unsigned long long val
	);

/**
	* Reduce the text given in original to a given number of bits and place in text
	* bits - number of bits to reduce original to
	* target - where to place reduced number 
	*/
void reduce (
	char original[16], 
	char target[16], 
	int bits
	);
/**
	* Hash plaintext using AES
	* Put hashed plaintext into char * given as cipher text
	*/
int hash (
	char plaintext[16], 
	char ciphertext[16], 
	aes_context ctx, 
	char key[16]
	);
/**
	* Run reduce(hash(plaintext)) rounds times and end with the result in plaintext
	*/
void hash_reduce_chain (
	char plaintext[16], 
	char ciphertext[16], 
	aes_context ctx, 
	char key[16],
	int rounds,
	int bits
	);

void copy(
	char *original, 
	char *target, 
	int len
	);

unsigned long long char128_to_long (
	char *target, 
	int bits
	);
