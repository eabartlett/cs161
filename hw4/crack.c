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
	printf("Password is 0x");
	for (int i = 16-left; i < 16; i++)
		printf("%02x", pass[i]&0xff);
	printf(". AES was evaluated %d times.\n", calls);
}

void nullify (char *target, int length)
{
	for (int i = 0; i < length; i++)
		target[i] = 0x00;
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

/*
 * Sets at 16 element char array given a 32 element string
 */
void set (
	unsigned char str[32],
	unsigned char out[16]
	)
{
	char *temp = malloc(2);
	temp[1] = 0x00;
	nullify(out, 16);
	for (int i = 0; i < 32; i+=2) {
		temp[0] = str[i];
		out[i/2] = strtoul(temp,NULL,16)<<4;
		temp[0] = str[i+1];
		out[i/2] |= strtoul(temp,NULL,16);
	}
	free(temp);
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

void match (
	FILE *fp,
	char target[], 
	char password[],
	aes_context ctx,
	long long length,
	int *aes_calls,
	int start,
	int n
	)
{
	int hash_match = -1;
	char temp[16], begin[16];
	nullify(temp, 16); nullify(begin, 16);
	while (hash_match < 0) {
		fseek(fp, 0, SEEK_SET);
		for (int i = 0; i < length; i++) {
			fread(&begin[start], 16-start, sizeof *begin, fp);
			fread(&temp[start], 16-start, sizeof *temp, fp);
			if (comp_chars(temp, password)) {
				hash_match =  i;
				break;
			}
		}
		hash_reduce_chain(password, ctx, 1, n);
		(*aes_calls)++;
	}
	copy(begin, target, 16);
}

int main (int argc, const char * argv[])
{
  FILE *fp;
  int s, n, leftover, start, read_pass, read_chain, pwd_size;
	long long  out_size;
  aes_context     ctx;
  unsigned char ciphertext[16], password[16], plaintext[16], hash_pass[16];
	
  if (argc < 4) {
		// Make sure valid arguments are given
    printf("Gentable takes 3 arguments, crack <n> <s> <hash>\n");
    return 0;
  }
	nullify(password, 16); nullify(plaintext, 16); nullify(hash_pass, 16);
	n = atoi(argv[1]); s = atoi(argv[2]);
	set(&argv[3][2], hash_pass);
	// > 0 if bits are past byte boundry - == 0 if exactly on byte boundry
	leftover = n % 8; 
	
	// Where in char * we store actual bits of password
	start = 16-(n/8 + (leftover > 0)); 

	// Size of both values to be written (password/reduced) in bytes	
	pwd_size = (16 - start) * 2; 

	// Number of entries we can fit in rainbow (2^s * 3 * 16/2)
	out_size = (1 << s) * 3 * 16; 
	out_size /= pwd_size;
	
	// Read in hashed password value	
	reduce(hash_pass, password, n);
	int aes_calls = 0; int r; int total= 0;
	int chain_len = (1 << (n-s))*pwd_size*2;
	fp = fopen("rainbow", "r+");
	printf("Outsize: %d\n", out_size);
	while (!(comp_chars(ciphertext, hash_pass)) & (total < out_size)) {
		total++;
		r = 0;
		match(fp, plaintext, password, ctx, out_size, &aes_calls, start, n);
		copy(plaintext, ciphertext, 16);
		do {
			r++;
			reduce(ciphertext, plaintext, n);
			hash(plaintext, ciphertext, ctx);
			aes_calls++;
		} while (!(comp_chars(ciphertext, hash_pass)) & (r < chain_len));
		if (!comp_chars(ciphertext, hash_pass)) {
			hash(password, ciphertext, ctx);
			reduce(ciphertext, password, n);
		}
	}
	if (total >= out_size)
		printf("Failure\n");
	else
		print_answer(plaintext, aes_calls, n);
	fclose(fp);

	return 0;
}
