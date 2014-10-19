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

print_answer (
	char pass[16],
	int calls,
	int bits
	)
{
	int left = (bits / 8) + ((bits % 8) > 0);
	printf("left: %d\n", left);
	printf("Password is 0x");
	for (int i = 16-left; i < 16; i++)
		printf("%02x", pass[i]&0xff);
	printf(". AES was evaluated %d times.\n", calls);
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
	* Run reduce(hash(plaintext)) rounds times and end with the result in password
	*/
void hash_reduce_chain (
	char password[16], 
	aes_context ctx, 
	int rounds,
	int bits
	)
{
	char temp[16];
	for (; rounds > 0; rounds--) {
		hash(password, temp, ctx);
		reduce(temp, password, bits);
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

int comp_chars (char c1[16], char c2[16])
{
	for (int i = 0; i < 16; i++) {
		if (memcmp(c1, c2, 16) != 0) {
			return 0;
		}
	}
	return 1;
}

int match (
	char r_table[][2][16], 
	char password[],
	aes_context ctx,
	long long length,
	int *aes_calls,
	int n
	)
{
	int hash_match = -1;
	while (hash_match < 0) {
		for (int i = 0; i < length; i++) {
			if (comp_chars(r_table[i][1], password))
				hash_match =  i;
		}
		hash_reduce_chain(password, ctx, 1, n);
		(*aes_calls)++;
	}
	return hash_match;
}

int main (int argc, const char * argv[])
{
  FILE *fp;
  int s, n, leftover, start, read_pass, read_chain, pwd_size;
	long long  out_size;
  aes_context     ctx;
  unsigned char ciphertext[16], password[16], plaintext[16], hash_pass[16], front[16], back[16];
	
  if (argc < 4) {
		// Make sure valid arguments are given
    printf("Gentable takes 3 arguments, crack <n> <s> <hash>\n");
    return 0;
  }
	nullify(password, 16); nullify(plaintext, 16); nullify(hash_pass, 16);
	n = atoi(argv[1]); s = atoi(argv[2]);
	hash_pass[0] = 0x97;
	hash_pass[1] = 0x0f;
	hash_pass[2] = 0xc1;
	hash_pass[3] = 0x6e;
	hash_pass[4] = 0x71;
	hash_pass[5] = 0xb7;
	hash_pass[6] = 0x54;
	hash_pass[7] = 0x63;
	hash_pass[8] = 0xab;
	hash_pass[9] = 0xaf;
	hash_pass[10] = 0xb3;
	hash_pass[11] = 0xf8;
	hash_pass[12] = 0xbe;
	hash_pass[13] = 0x93;
	hash_pass[14] = 0x9d;
	hash_pass[15] = 0x1c;
	// > 0 if bits are past byte boundry - == 0 if exactly on byte boundry
	leftover = n % 8; 
	
	// Where in char * we store actual bits of password
	start = 16-(n/8 + (leftover > 0)); 

	// Size of both values to be written (password/reduced) in bytes	
	pwd_size = (16 - start) * 2; 

	// Number of entries we can fit in rainbow (2^s * 3 * 16/2)
	out_size = (2 << (s-1)) * 3 * 16; 
	out_size /= pwd_size;
	
	unsigned char r_table[out_size][2][16];

	fp = fopen("rainbow", "r+");
	// Read rainbow table into memory
	for (int i = 0; i < out_size; i++) {
		fread(&password[start], 16-start, sizeof *password, fp);
		fread(&plaintext[start], 16-start, sizeof *plaintext, fp);
		copy(password, r_table[i][0], 16);
		copy(plaintext, r_table[i][1], 16);
	} 
	fclose(fp);
	
	// Read in hashed password value	
	reduce(hash_pass, password, n);
	int aes_calls = 0; int r;
	while (!(comp_chars(ciphertext, hash_pass))) {
		r = 0;
		int hash_match = match(r_table, password, ctx, out_size, &aes_calls, n);
		copy(r_table[hash_match][0], ciphertext, 16);
		do {
			r++;
			reduce(ciphertext, password, n);
			hash(password, ciphertext, ctx);
			aes_calls++;
		} while (!(comp_chars(ciphertext, hash_pass)) & (r < 200));
	}
	print_answer(password, aes_calls, n);

	return 0;
}
