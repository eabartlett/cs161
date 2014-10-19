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

void nullify (char *target, length)
{
	for (int i = 0; i < length; i++)
		target[i] = 0x00;
}

/**
	* Hash plaintext using AES
	* Put hashed plaintext into char * given as cipher text
	*/
int hash (
	char password[16], 
	char ciphertext[16], 
	aes_context ctx 
	)
{
	char null_arr[16];
	nullify(null_arr, 16);
  if (aes_setkey_enc (&ctx, password, 128)) {
    printf("Error setting key password\n");
    return 1;
  }
  if (aes_crypt_ecb (&ctx, AES_ENCRYPT, null_arr, ciphertext)) {
    printf("Error encrypting password\n");
		return 1;
  }
	return 0;
}

/**
	* Run reduce(hash(plaintext)) rounds times and end with the result in plaintext
	*/
void hash_reduce_chain (
	char password[16], 
	char ciphertext[16], 
	aes_context ctx, 
	int rounds,
	int bits
	)
{
	for (; rounds > 0; rounds--) {
		hash(password, ciphertext, ctx);
		reduce(ciphertext, password, bits);
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

int main (int argc, const char * argv[])
{
  if (argc < 3) {
		// Make sure valid arguments are given
    printf("Gentable takes 2 arguments, gentable <n> <s>\n");
    return 0;
  }

  FILE *fp;
  int s, n, leftover, start, pwd_size, chain_len;
	long long  out_size;
  aes_context     ctx;
	n = atoi(argv[1]); s = atoi(argv[2]);
	
	// > 0 if bits are past byte boundry - == 0 if exactly on byte boundry
	leftover = n % 8; 
	
	// Where in char * we store actual bits of password
	start = 16-(n/8 + (leftover > 0)); 

	// Size of both values to be written (password/reduced) in bytes	
	pwd_size = (16 - start) * 2; 

	// Number of entries we can fit in rainbow (2^s * 3 * 16/2)
	out_size = (1 << s) * 3 * 16; 
	out_size /= pwd_size;
	
	// Set number of hash_reduces to do per chain
	chain_len = 50 * (n/s) + (s > n);
	
  unsigned char password[16], ciphertext[16], key[16], plaintext[16];
	for (int i = 0; i < 16; i++) {
		key[i] = 0xFF;
	}

	fp = fopen("rainbow", "w+");
	printf("Size of chain: %d\n", chain_len);
	for (unsigned long long pass = 0; pass < out_size; pass++) {
		assign(password, pass);
		copy(password, plaintext, 16);
		hash_reduce_chain(plaintext, ciphertext, ctx, chain_len, n);
		fwrite(&password[start], 16-start, sizeof *password, fp);
		fwrite(&plaintext[start], 16-start, sizeof *plaintext, fp);
	}
  
	fclose(fp);
  
	return 0;
}
