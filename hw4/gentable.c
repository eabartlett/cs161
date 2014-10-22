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
	* get_val -- return an unsigned in contained in the least significant bits 
	* of a 16 byte char array pass
	*/
unsigned int get_val (unsigned char *in, int bits)
{
	int i; int res = 0;
	int left = bits % 8;
	int start = 16 - ((bits/8) + (left > 0));
	for (i = start; i < 16; i++) {
		res = (res << 8) | (unsigned int) in[i];
	}
	return res;
}

/**
	* get_or_set -- return the value of nth bit (where n is the integer value of a password
	* of bits bits long) in the bitmap char array - if it is 0 set it to 1
	*/
int get_or_set (char *password, char *bitmap, int bits)
{
	unsigned int len = (1 << bits)/8;
	unsigned int bit = get_val(password, bits);
	unsigned int left = bit % 8;
	unsigned int index = bit/8 + (left > 0);
	int prev =  (int) (bitmap[len-index] & (1 << (left - 1))) >> (left - 1);
	if (!prev)
		bitmap[len-index] |= (1 << (left - 1));
	return prev;
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

void nullify (char *target, int length)
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
int hash_reduce_chain (
	char password[16], 
	char ciphertext[16], 
	aes_context ctx, 
	int rounds,
	int bits
	)
{
	char *bitmap = malloc((1<<bits)/8);
	nullify(bitmap, (1<<bits)/8);
	for (int i = 0; rounds > i; i++) {
		hash(password, ciphertext, ctx);
		reduce(ciphertext, password, bits);
		if (get_or_set(password, bitmap, bits)) {
			free(bitmap);
			return i;
		}
	}
	free(bitmap);
	return rounds;
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
  unsigned char password[16], ciphertext[16], key[16], plaintext[16];
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
	chain_len = (1 << (n-s))*pwd_size*2;
	int min_chain = (1 << (n-s))*pwd_size/2;
	
	for (int i = 0; i < 16; i++) {
		key[i] = 0xFF;
	}
	fp = fopen("rainbow", "w+");
	int pass = 0;
	int bad_pass = 0;
	for (unsigned int written = 0; written < out_size; written++) {
		int chain = 0;
		do {
			assign(password, pass);
			copy(password, plaintext, 16);
			chain = hash_reduce_chain(plaintext, ciphertext, ctx, chain_len, n);
			pass++;
			if (chain < min_chain)
				bad_pass++;
		} while (chain < min_chain);
		fwrite(&password[start], 16-start, sizeof *password, fp);
		fwrite(&plaintext[start], 16-start, sizeof *plaintext, fp);
	}
  printf("Colliding passwords: %d\n", bad_pass);
	fclose(fp);
  
	return 0;
}
