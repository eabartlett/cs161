#include "stdio.h"
#include "stdlib.h"
#include "aes.h"

/**
	* Print an array of chars of a given length
	*/
void print_chars (
	char *chars, 
	int len
	)
{
	for (int i = 0; i < len; i++){
		printf("%02x", chars[i]&0xff);
	}
	printf("\n");
}

/*
 *  assign -- transform long long (64 bit unsigned integer) val to 16 byte array pass
 */

void assign (
	unsigned char *pass, 
	unsigned long long val
	)
{
	int i;
	for (i = 15; i >= 8; i--)	{
		pass[i] = (unsigned char) val & 0xFF;
		val >>= 8;
	}
	for (i =7; i >= 0; i--)
		pass[i] = 0;
}

/**
	* Reduce the text given in original to a given number of bits and place in text
	* bits - number of bits to reduce original to
	* target - where to place reduced number 
	*/
void reduce (
	char original[16], 
	char target[16], 
	int bits
	)
{
	int leftovers; int ander = 0;
	for(int i = 0; i<16-(bits/8); i++)
		target[i] &= 0x00;
	leftovers = bits % 8;
	for (int i = leftovers; i > 0; i--)
		ander = (ander << 1) | 1;
	int start = (16-(bits/8))- (leftovers > 0);
	for (int i = start; i < 16; i++) {
		if (leftovers) {
			target[i] = original[i] & ander;
			leftovers = 0;
		} else {
			target[i] = original[i];
		}
	}
}

/**
	* Hash plaintext using AES
	* Put hashed plaintext into char * given as cipher text
	*/
int hash (
	char plaintext[16], 
	char ciphertext[16], 
	aes_context ctx, 
	char key[16]
	)
{
  if (aes_setkey_enc (&ctx, key, 128)) {
    printf("Error setting key password\n");
    return 1;
  }
  if (aes_crypt_ecb (&ctx, AES_ENCRYPT, plaintext, ciphertext)) {
    printf("Error encrypting password\n");
		return 1;
  }
	return 0;
}

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
	)
{
	for (; rounds > 0; rounds--) {
		hash(plaintext, ciphertext, ctx, key);
		reduce(ciphertext, plaintext, bits);
	}
}

void copy(
	char *original, 
	char *target, 
	int len
	)
{
	for (int i = 0; i < len; i++)
		target[i] = original[i];
}

unsigned long long char128_to_long (
	char *target, 
	int bits
	)
{
	unsigned long long res = 0;
	for (; bits > 0; bits -= 8) {
		res |= (target[16-(bits/8)] << (bits - 8));
	}
	return res;
}

void nullify (char *target, length)
{
	for (int i = 0; i < length; i++)
		target[i] = 0x00;
}

int main (int argc, const char * argv[])
{
  FILE *fp;
  int s, n, leftover, start, read_pass, read_chain;
  aes_context     ctx;
  unsigned char password[16], ciphertext[16], key[16], plaintext[16], hash[16];
	unsigned char chains[128][2][16];
	
  if (argc < 4) {
		// Make sure valid arguments are given
    printf("Gentable takes 3 arguments, crack <n> <s> <hash>\n");
    return 0;
  }

	n = atoi(argv[1]);
  s = 2;
	leftover = n % 8;
	start = 16-(n/8 + (leftover > 0));
	for (int i = 0; i < 16; i++) {
		key[i] = 0xFF;
	}
	for (int i = 0; i < 128; i++) {
		nullify(chains[i][0], 16);
		nullify(chains[i][1], 16);
	}
	nullify(password, 16); nullify(ciphertext, 16); nullify(key, 16); nullify(plaintext, 16); nullify(hash, 16);
	fp = fopen("rainbow", "r+");
	int i = 0;
	do {
		read_pass = fread(&password[start], 16-start, sizeof *password, fp);
		read_chain = fread(&plaintext[start], 16-start, sizeof *plaintext, fp);
		copy(&password, &chains[i][0], 16);
		copy(&plaintext, &chains[i][1], 16);
		i++;
	} while (read_pass > 0 & read_chain > 0);
	for(int i = 0; i < 2; i++) {
		print_chars(chains[i][0], 16);
		print_chars(chains[i][1], 16);
	}
	fclose(fp);
}
