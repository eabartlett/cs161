#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <gmp.h>

static void perform_rsa(mpz_t result, mpz_t message, mpz_t d, mpz_t n);
static void usage();
static int hex_to_ascii(char a, char b);
static int hex_to_int(char a);

int main(int argc, char **argv) {
    mpz_t result, message, d, n;
    FILE *message_file, *d_file, *n_file;
    size_t bytes_read;
    int c, i, err, option_index;
    char *result_str;
    message_file = d_file = n_file = 0;
    option_index = 0;
    err = 0;

    static struct option long_options[] = {
	{"message", required_argument, 0, 'm'},
	{"exp", required_argument, 0, 'd'},
	{"modulus", required_argument, 0, 'n'},
	{0, 0, 0, 0},
    };

    while (1) {
	c = getopt_long(argc, argv, "d:n:m:", long_options, &option_index);
	if (c < 0) {
	    break;
	}
	switch(c) {
	case 0:
            usage();
	    break;
	case 'd':
	    d_file = fopen(optarg, "r");
	    if (d_file == NULL) {
		perror("Key file error");
		exit(1);
	    }
	    break;
	case 'm':
	    message_file = fopen(optarg, "r");
	    if (message_file == NULL) {
		perror("Message file error");
		exit(1);
	    }
	    break;
	case 'n':
	    n_file = fopen(optarg, "r");
	    if (n_file == NULL) {
		perror("Modulus file error");
		exit(1);
	    }
	    break;
	case '?':
	    usage();
	    break;
	default:
	    usage();
	    break;
	}
    }

    if (message_file == NULL || n_file == NULL || d_file == NULL) {
        usage();
    }

    mpz_init(result);
    mpz_init(message);
    bytes_read = mpz_inp_str(message, message_file, 0);
    if (bytes_read <= 0) {
	err = 1;
    }
    mpz_init(d);
    bytes_read = mpz_inp_str(d, d_file, 0);
    if (bytes_read <= 0) {
	err = 1;
    }
    mpz_init(n);
    bytes_read = mpz_inp_str(n, n_file, 0);
    if (bytes_read <= 0) {
	err = 1;
    }

    if (err == 1) {
	printf("%s\n", "Error: cannot read one or more files. See spec for usage.");
	exit(1);
    }

    /* Computes RSA using the specified parameters and stores the value in RESULT. */
    perform_rsa(result, message, d, n);

    result_str = mpz_get_str(NULL, 16, result);
    i = 0;
    while(result_str[i] != '\0') {
	printf("%c", hex_to_ascii(result_str[i], result_str[i+1]));
	i+=2;
    }

    mpz_clear(result);
    mpz_clear(message);
    mpz_clear(d);

    return 0;
}

/*
 * @param result: a field to populate with the result of your RSA calculation.
 * @param message: the message to perform RSA on. (probably a cert in this case)
 * @param d: the encryption key from the key_file passed in through the command-line arguments
 * @param n: the modulus for RSA from the modulus_file passed in through the command-line arguments
 *
 * Fill in the method using the repeated squares method of calculating RSA. Store the result in the provided result argument.
 * See spec for more implementation details.
 */
static void
perform_rsa(mpz_t result, mpz_t message, mpz_t d, mpz_t n)
{
    mpz_t two; mpz_t one; mpz_t zero; mpz_t comp;
    mpz_init(zero); mpz_init(one); mpz_init(two); mpz_init(comp);
    mpz_set_str(two, "2", 10); mpz_set_str(one, "1", 10);
    mpz_add(result, result, one);
    
    while (mpz_cmp(zero, d) < 0) {
        mpz_mod(comp, d, two);
        if (mpz_cmp(comp, zero) > 0) {
            mpz_mul(result, result, message);
            mpz_mod(result, result, n);
            mpz_sub(d, d, one);
        }
        mpz_mul(message, message, message);
        mpz_mod(message, message, n);
        mpz_div(d, d, two);
    }
    mpz_clear(two); mpz_clear(one); mpz_clear(zero); mpz_clear(comp);
}

static void
usage()
{
    printf("./proj0 -m <message_file> -n <modulus_file> -d <key_file>\n");
    exit(1);
}

static int
hex_to_ascii(char a, char b)
{
    int high = hex_to_int(a) * 16;
    int low = hex_to_int(b);
    return high + low;
}

static int
hex_to_int(char a)
{
    if (a >= 97) {
	a -= 32;
    }
    int first = a / 16 - 3;
    int second = a % 16;
    int result = first*10 + second;
    if (result > 9) {
	result -= 1;
    }
    return result;
}
