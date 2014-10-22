#include <stdio.h>
unsigned int get_val (unsigned char *in, bits)
{
	int i; int res = 0;
	int left = bits % 8;
	int start = 16 - ((bits/8) + (left > 0));
	for (i = start; i < 16; i++) {
		printf("%02x", in[i]&0xff);
		res = (res << 8) | (unsigned int) in[i];
	}
	printf("\n");
	return res;
}
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
void main ()
{
	char password[16], ciphertext[16], bitmap[(1 << 12)/8];
	for (int i = 0; i < 16; i++)
		password[i] = 0x00;
	password[15] = 0x01;

	for (int i = 0; i < ((1<<12)/8); i++)
		bitmap[i] = 0x00;

	for (int i = 0; i < 16; i++)
		printf("%02x", password[i]&0xff);
	printf("\n");
	get_or_set(password, bitmap, 12); 
	for (int i = 0; i < ((1<<12)/8); i++)
		printf("%02x", bitmap[i]&0xff);
	printf("\n");
}
