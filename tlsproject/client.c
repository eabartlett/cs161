/*
 * sig_client.c
 *
 * Author: Alec Guertin
 * University of California, Berkeley
 * CS 161 - Computer Security
 * Fall 2014 Semester
 * Project 1
 */

#include "client.h"

/* The file descriptor for the socket connected to the server. */
static int sockfd;

static void perform_rsa(mpz_t result, mpz_t message, mpz_t d, mpz_t n);
static int hex_to_ascii(char a, char b);
static int hex_to_int(char a);
static void usage();
static void kill_handler(int signum);
static int random_int();
static void cleanup();
static void mpz_to_char(char *dest, mpz_t src, int len);
void decrypt_master_secret(mpz_t decrypted_ms, ps_msg *ms_ver, mpz_t key_exp, mpz_t key_mod);

int main(int argc, char **argv) {
  int err, option_index, c, clientlen, counter;
  unsigned char rcv_plaintext[AES_BLOCK_SIZE];
  unsigned char rcv_ciphertext[AES_BLOCK_SIZE];
  unsigned char send_plaintext[AES_BLOCK_SIZE];
  unsigned char send_ciphertext[AES_BLOCK_SIZE];
  aes_context enc_ctx, dec_ctx;
  in_addr_t ip_addr;
  struct sockaddr_in server_addr;
  FILE *c_file, *d_file, *m_file;
  ssize_t read_size, write_size;
  struct sockaddr_in client_addr;
  tls_msg err_msg, send_msg, rcv_msg;
  mpz_t client_exp, client_mod;
  fd_set readfds;
  struct timeval tv;

  c_file = d_file = m_file = NULL;

  mpz_init(client_exp);
  mpz_init(client_mod);

  /*
   * This section is networking code that you don't need to worry about.
   * Look further down in the function for your part.
   */

  memset(&ip_addr, 0, sizeof(in_addr_t));

  option_index = 0;
  err = 0;

  static struct option long_options[] = {
    {"ip", required_argument, 0, 'i'},
    {"cert", required_argument, 0, 'c'},
    {"exponent", required_argument, 0, 'd'},
    {"modulus", required_argument, 0, 'm'},
    {0, 0, 0, 0},
  };

  while (1) {
    c = getopt_long(argc, argv, "c:i:d:m:", long_options, &option_index);
    if (c < 0) {
      break;
    }
    switch(c) {
    case 0:
      usage();
      break;
    case 'c':
      c_file = fopen(optarg, "r");
      if (c_file == NULL) {
	perror("Certificate file error");
	exit(1);
      }
      break;
    case 'd':
      d_file = fopen(optarg, "r");
      if (d_file == NULL) {
	perror("Exponent file error");
	exit(1);
      }
      break;
    case 'i':
      ip_addr = inet_addr(optarg);
      break;
    case 'm':
      m_file = fopen(optarg, "r");
      if (m_file == NULL) {
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

  if (d_file == NULL || c_file == NULL || m_file == NULL) {
    usage();
  }
  if (argc != 9) {
    usage();
  }

  mpz_inp_str(client_exp, d_file, 0);
  mpz_inp_str(client_mod, m_file, 0);

  signal(SIGTERM, kill_handler);

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("Could not open socket");
    exit(1);
  }

  memset(&server_addr, 0, sizeof(struct sockaddr_in));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = ip_addr;
  server_addr.sin_port = htons(HANDSHAKE_PORT);
  err = connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr));
  if (err < 0) {
    perror("Could not bind socket");
    cleanup();
  }

  // YOUR CODE HERE
  // IMPLEMENT THE TLS HANDSHAKE

	// Create, send, and receive the hello messages.
  int client_random, server_random, sent;
  client_random = random_int();
  hello_message *client_hello = malloc(HELLO_MSG_SIZE);
  client_hello->type = CLIENT_HELLO;
  client_hello->random = client_random;
  client_hello->cipher_suite = TLS_RSA_WITH_AES_128_ECB_SHA256;
  sent = send_tls_message(sockfd, client_hello, HELLO_MSG_SIZE);
  if (sent) {
	exit(ERR_FAILURE);
  } 
  hello_message *server_hello = malloc(HELLO_MSG_SIZE);
  receive_tls_message(sockfd, server_hello, HELLO_MSG_SIZE, SERVER_HELLO);
  server_random = server_hello->random;

  // Create, send, and receive the certificates.
  cert_message *client_cert = malloc(CERT_MSG_SIZE);
  client_cert->type = CLIENT_CERTIFICATE;
  fread(client_cert->cert, 1, RSA_MAX_LEN, c_file);
  send_tls_message(sockfd, client_cert, CERT_MSG_SIZE);
  cert_message *server_cert_msg = malloc(CERT_MSG_SIZE);
  receive_tls_message(sockfd, server_cert_msg, CERT_MSG_SIZE, SERVER_CERTIFICATE);

  // Find the public key from the certificate.
  char *server_cert_char = malloc(RSA_MAX_LEN);
  mpz_t server_exp; mpz_t server_mod; mpz_t ca_mod; mpz_t ca_exp; mpz_t server_cert;

  mpz_init(server_exp); mpz_init(server_mod); mpz_init(server_cert);
  mpz_init(ca_exp); mpz_init(ca_mod);
	
  mpz_set_str(ca_mod, CA_MODULUS+2, 16); mpz_set_str(ca_exp, CA_EXPONENT+2, 16);
  decrypt_cert(server_cert ,server_cert_msg, ca_exp, ca_mod);
  mpz_get_ascii(server_cert_char, server_cert);
  get_cert_exponent(server_exp, server_cert_char);
  get_cert_modulus(server_mod, server_cert_char);
  free(server_cert_char);

  // Compute the PreMaster Secret.
  ps_msg  *encrypted_master_secret = malloc(PS_MSG_SIZE);
  mpz_t pms; mpz_t pm_secret; mpz_t master_secret; mpz_t verify_secret_mpz;
  mpz_init(pms); mpz_init(pm_secret); mpz_init(master_secret); mpz_init(verify_secret_mpz);

  int pm_value = random_int();
  mpz_set_ui(pms, pm_value);
  perform_rsa(pm_secret, pms, server_exp, server_mod);

  ps_msg *pms_msg = malloc(PS_MSG_SIZE);
  pms_msg->type = PREMASTER_SECRET;
  mpz_get_str(pms_msg->ps, 16, pm_secret);

  send_tls_message(sockfd, pms_msg, PS_MSG_SIZE);

  // Receive the Master Secret
  char verify_secret[16];
  receive_tls_message(sockfd, encrypted_master_secret, PS_MSG_SIZE, VERIFY_MASTER_SECRET);
  decrypt_master_secret(master_secret, encrypted_master_secret, client_exp, client_mod);
  compute_master_secret(pm_value, client_random, server_random, verify_secret);
  mpz_set_str(verify_secret_mpz, hex_to_str(verify_secret, 16), 16);
  if (verify_master_secret(master_secret, verify_secret_mpz)) {
    printf("Error, master secret is not valid!\n");
    exit(ERR_FAILURE);
  }

  /*
   * START ENCRYPTED MESSAGES
   */

  memset(send_plaintext, 0, AES_BLOCK_SIZE);
  memset(send_ciphertext, 0, AES_BLOCK_SIZE);
  memset(rcv_plaintext, 0, AES_BLOCK_SIZE);
  memset(rcv_ciphertext, 0, AES_BLOCK_SIZE);

  memset(&rcv_msg, 0, TLS_MSG_SIZE);

  aes_init(&enc_ctx);
  aes_init(&dec_ctx);

  // YOUR CODE HERE
  //Free all malloc'd memory
  free(client_hello); free(client_cert);
  free(server_hello); free(server_cert_msg);
  free(pms_msg); free(encrypted_master_secret);
  mpz_clear(pms); mpz_clear(pm_secret);
  mpz_clear(server_exp); mpz_clear(server_mod); mpz_clear(server_cert);
  mpz_clear(ca_exp); mpz_clear(ca_mod);
  mpz_clear(verify_secret_mpz);
  // SET AES KEYS
  if (aes_setkey_enc(&enc_ctx, verify_secret, 128)) {
    printf("Error: problem setting the encryption key\n");
    exit(ERR_FAILURE);
  }
  if (aes_setkey_dec(&dec_ctx, verify_secret, 128)) {
    printf("Error: problem setting the decryption key\n");
    exit(ERR_FAILURE);
  }
  printf("Read to send messages.\n");

  fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
  /* Send and receive data. */
  while (1) {
    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO, &readfds);
    FD_SET(sockfd, &readfds);
    tv.tv_sec = 2;
    tv.tv_usec = 10;

    select(sockfd+1, &readfds, NULL, NULL, &tv);
    if (FD_ISSET(STDIN_FILENO, &readfds)) {
      counter = 0;
      memset(&send_msg, 0, TLS_MSG_SIZE);
      send_msg.type = ENCRYPTED_MESSAGE;
      memset(send_plaintext, 0, AES_BLOCK_SIZE);
      read_size = read(STDIN_FILENO, send_plaintext, AES_BLOCK_SIZE);
      while (read_size > 0 && counter + AES_BLOCK_SIZE < TLS_MSG_SIZE - INT_SIZE) {
	if (read_size > 0) {
	  err = aes_crypt_ecb(&enc_ctx, AES_ENCRYPT, send_plaintext, send_ciphertext);
	  memcpy(send_msg.msg + counter, send_ciphertext, AES_BLOCK_SIZE);
	  counter += AES_BLOCK_SIZE;
	}
	memset(send_plaintext, 0, AES_BLOCK_SIZE);
	read_size = read(STDIN_FILENO, send_plaintext, AES_BLOCK_SIZE);
      }
      write_size = write(sockfd, &send_msg, INT_SIZE+counter+AES_BLOCK_SIZE);
      if (write_size < 0) {
	perror("Could not write to socket");
	cleanup();
      }
    } else if (FD_ISSET(sockfd, &readfds)) {
      memset(&rcv_msg, 0, TLS_MSG_SIZE);
      memset(rcv_ciphertext, 0, AES_BLOCK_SIZE);
      read_size = read(sockfd, &rcv_msg, TLS_MSG_SIZE);
      if (read_size > 0) {
	if (rcv_msg.type != ENCRYPTED_MESSAGE) {
	  goto out;
	}
	memcpy(rcv_ciphertext, rcv_msg.msg, AES_BLOCK_SIZE);
	counter = 0;
	while (counter < read_size - INT_SIZE - AES_BLOCK_SIZE) {
	  aes_crypt_ecb(&dec_ctx, AES_DECRYPT, rcv_ciphertext, rcv_plaintext);
	  printf("%s", rcv_plaintext);
	  counter += AES_BLOCK_SIZE;
	  memcpy(rcv_ciphertext, rcv_msg.msg+counter, AES_BLOCK_SIZE);
	}
	printf("\n");
      }
    }

  }

 out:
  close(sockfd);
  return 0;
}

/*
 * \brief                  Decrypts the certificate in the message cert.
 *
 * \param decrypted_cert   This mpz_t stores the final value of the binary
 *                         for the decrypted certificate. Write the end
 *                         result here.
 * \param cert             The message containing the encrypted certificate.
 * \param key_exp          The exponent of the public key for decrypting
 *                         the certificate.
 * \param key_mod          The modulus of the public key for decrypting
 *                         the certificate.
 */
void
decrypt_cert(mpz_t decrypted_cert, cert_message *cert_msg, mpz_t key_exp, mpz_t key_mod)
{
  mpz_t encrypted_s_cert;	
	mpz_init(encrypted_s_cert);
  mpz_set_str(encrypted_s_cert, (cert_msg->cert)+2, 16);

	perform_rsa(decrypted_cert, encrypted_s_cert, key_exp, key_mod);
	mpz_clear(encrypted_s_cert);
}

/*
 * \brief                  Decrypts the master secret in the message ms_ver.
 *
 * \param decrypted_ms     This mpz_t stores the final value of the binary
 *                         for the decrypted master secret. Write the end
 *                         result here.
 * \param ms_ver           The message containing the encrypted master secret.
 * \param key_exp          The exponent of the public key for decrypting
 *                         the master secret.
 * \param key_mod          The modulus of the public key for decrypting
 *                         the master secret.
 */
void
decrypt_master_secret(mpz_t decrypted_ms, ps_msg *ms_ver, mpz_t key_exp, mpz_t key_mod)
{
	mpz_t encrypted;
	mpz_init(encrypted);
	mpz_set_str(encrypted, ms_ver->ps, 16);
  perform_rsa(decrypted_ms, encrypted, key_exp, key_mod);
	mpz_clear(encrypted);
}

/*
 * \brief                  Computes the master secret.
 *
 * \param ps               The premaster secret.
 * \param client_random    The random value from the client hello.
 * \param server_random    The random value from the server hello.
 * \param master_secret    A pointer to the final value of the master secret.
 *                         Write the end result here.
 */
void
compute_master_secret(int ps, int client_random, int server_random, unsigned char *master_secret)
{
  SHA256_CTX ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, &ps, INT_SIZE);
  sha256_update(&ctx, &client_random, INT_SIZE);
  sha256_update(&ctx, &server_random, INT_SIZE);
  sha256_update(&ctx, &ps, INT_SIZE);
  sha256_final(&ctx, master_secret);
}
/*
 * \brief                 Verifies that the master secret is valid.
 *
 *
 * \param master_secret   The secret received from the server.
 * \param verify_secret   The secret computed by us.
 */
int
verify_master_secret(mpz_t master_secret, mpz_t verify_secret)
{
	return mpz_cmp(master_secret, verify_secret);
}
/*
 * \brief                  Sends a message to the connected server.
 *                         Returns an error code.
 *
 * \param socketno         A file descriptor for the socket to send
 *                         the message on.
 * \param msg              A pointer to the message to send.
 * \param msg_len          The length of the message in bytes.
 */
int
send_tls_message(int socketno, void *msg, int msg_len)
{
  int written = write(socketno, msg, msg_len);
  if (msg_len == written)
  	return 0;
  return 1;
}

/*
 * \brief                  Receieves a message from the connected server.
 *                         Returns an error code.
 *
 * \param socketno         A file descriptor for the socket to receive
 *                         the message on.
 * \param msg              A pointer to where to store the received message.
 * \param msg_len          The length of the message in bytes.
 * \param msg_type         The expected type of the message to receive.
 */
int
receive_tls_message(int socketno, void *msg, int msg_len, int msg_type)
{
	// read in msg
	int r = read(socketno, msg, msg_len);
	if (msg_type == CLIENT_HELLO | msg_type == SERVER_HELLO) {
		if (((hello_message*)msg)->type != msg_type) {
			printf("Error, wrong error type. Expecting %d, found %d\n", msg_type, ((hello_message*)msg)->type);
			exit(ERR_FAILURE);
		}
	}
	if (msg_type == CLIENT_CERTIFICATE | msg_type == SERVER_CERTIFICATE) {
		if (((cert_message*)msg)->type != msg_type) {
			printf("Error, wrong error type. Expecting %d, found %d\n", msg_type, ((cert_message*)msg)->type);
			exit(ERR_FAILURE);
		}
	}
	if (msg_type == PREMASTER_SECRET | msg_type == VERIFY_MASTER_SECRET) {
		if (((ps_msg*)msg)->type != msg_type) {
			printf("Error, wrong error type. Expecting %d, found %d\n", msg_type, ((ps_msg*)msg)->type);
			exit(ERR_FAILURE);
		}
	}
	if (msg_type == ENCRYPTED_MESSAGE) {
		if (((tls_msg*)msg)->type != msg_type) {
			printf("Error, wrong error type. Expecting %d, found %d\n", msg_type, ((tls_msg*)msg)->type);
			exit(ERR_FAILURE);
		}
	}
	if (msg_type == ERROR_MESSAGE) {
			printf("Error, wrong error type. Expecting %d, found %d\n", msg_type, ((hello_message*)msg)->type);
		exit(ERR_FAILURE);
	}
	return 0;
}


/*
 * \brief                Encrypts/decrypts a message using the RSA algorithm.
 *
 * \param result         a field to populate with the result of your RSA calculation.
 * \param message        the message to perform RSA on. (probably a cert in this case)
 * \param e              the encryption key from the key_file passed in through the
 *                       command-line arguments
 * \param n              the modulus for RSA from the modulus_file passed in through
 *                       the command-line arguments
 *
 * Fill in this function with your proj0 solution or see staff solutions.
 */
static void
perform_rsa(mpz_t result, mpz_t message, mpz_t e, mpz_t n)
{
    mpz_t two; mpz_t one; mpz_t zero; mpz_t comp; mpz_t e2; mpz_t n2;
    mpz_init(zero); mpz_init(one); mpz_init(two); mpz_init(comp); mpz_init(e2); mpz_init(n2);
		mpz_set(e2, e); mpz_set(n2, n);
    mpz_set_str(two, "2", 10); mpz_set_str(one, "1", 10);
    mpz_add(result, result, one);

    while (mpz_cmp(zero, e2) < 0) {
        mpz_mod(comp, e2, two);
        if (mpz_cmp(comp, zero) > 0) {
            mpz_mul(result, result, message);
            mpz_mod(result, result, n2);
            mpz_sub(e2, e2, one);
        }
        mpz_mul(message, message, message);
        mpz_mod(message, message, n2);
        mpz_div(e2, e2, two);
    }
    mpz_clear(two); mpz_clear(one); mpz_clear(zero); mpz_clear(comp); mpz_clear(e2); mpz_clear(n2);
}


/* Returns a pseudo-random integer. */
static int
random_int()
{
  srand(time(NULL));
  return rand();
}

/*
 * \brief                 Returns ascii string from a number in mpz_t form.
 *
 * \param output_str      A pointer to the output string.
 * \param input           The number to convert to ascii.
 */
void
mpz_get_ascii(char *output_str, mpz_t input)
{
  int i,j;
  char *result_str;
  result_str = mpz_get_str(NULL, HEX_BASE, input);
  i = 0;
  j = 0;
  while (result_str[i] != '\0') {
    output_str[j] = hex_to_ascii(result_str[i], result_str[i+1]);
    j += 1;
    i += 2;
  }
}

/*
 * \brief                  Returns a pointer to a string containing the
 *                         characters representing the input hex value.
 *
 * \param data             The input hex value.
 * \param data_len         The length of the data in bytes.
 */
char
*hex_to_str(char *data, int data_len)
{
  int i;
  char *output_str = calloc(1+2*data_len, sizeof(char));
  for (i = 0; i < data_len; i += 1) {
    snprintf(output_str+2*i, 3, "%02X", (unsigned int) (data[i] & 0xFF));
  }
  return output_str;
}

/* Return the public key exponent given the decrypted certificate as string. */
int
get_cert_exponent(mpz_t result, char *cert)
{
  int err;
  char *srch, *srch2;
  char exponent[RSA_MAX_LEN/2];
  memset(exponent, 0, RSA_MAX_LEN/2);
  srch = strchr(cert, '\n');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 1;
  srch = strchr(srch, '\n');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 1;
  srch = strchr(srch, '\n');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 1;
  srch = strchr(srch, ':');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 2;
  srch2 = strchr(srch, '\n');
  if (srch2 == NULL) {
    return ERR_FAILURE;
  }
  strncpy(exponent, srch, srch2-srch);
  err = mpz_set_str(result, exponent, 0);
  if (err == -1) {
    return ERR_FAILURE;
  }
  return ERR_OK;
}

/* Return the public key modulus given the decrypted certificate as string. */
int
get_cert_modulus(mpz_t result, char *cert)
{
  int err;
  char *srch, *srch2;
  char modulus[RSA_MAX_LEN/2];
  memset(modulus, 0, RSA_MAX_LEN/2);
  srch = strchr(cert, '\n');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 1;
  srch = strchr(srch, '\n');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 1;
  srch = strchr(srch, ':');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 2;
  srch2 = strchr(srch, '\n');
  if (srch2 == NULL) {
    return ERR_FAILURE;
  }
  strncpy(modulus, srch, srch2-srch);
  err = mpz_set_str(result, modulus, 0);
  if (err == -1) {
    return ERR_FAILURE;
  }
  return ERR_OK;
}

/* Prints the usage string for this program and exits. */
static void
usage()
{
    printf("./client -i <server_ip_address> -c <certificate_file> -m <modulus_file> -d <exponent_file>\n");
    exit(1);
}

/* Catches the signal from C-c and closes connection with server. */
static void
kill_handler(int signum)
{
  if (signum == SIGTERM) {
    cleanup();
  }
}

/* Converts the two input hex characters into an ascii char. */
static int
hex_to_ascii(char a, char b)
{
    int high = hex_to_int(a) * 16;
    int low = hex_to_int(b);
    return high + low;
}

/* Converts a hex value into an int. */
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

/* Closes files and exits the program. */
static void
cleanup()
{
  close(sockfd);
  exit(1);
}

/* Takes value of mpz_t and places it into the array of char given 
	 
	 Sadly I found a way to do the project without using this function
	 so it has to sit here, unused, in all of its glory.
*/
static void
mpz_to_char(char *dest, mpz_t src, int len)
{
	int i, actual_len; mpz_t hldr; char tmp[3]; char *hex;

	hex = mpz_get_str(NULL, 16, src);
	actual_len = strlen(hex);
	mpz_init(hldr);
	tmp[2] = 0x00;
	if ((len % 2 == 0) & !(actual_len % 2)) {
		for (i = 0; i < actual_len; i+=2) {
			strncpy(tmp, hex+i, 2);
			mpz_set_str(hldr, tmp, 16);
			dest[i/2] = 0xff & mpz_get_ui(hldr);
		}
	}
	if ((len % 2) & (actual_len % 2)) {
		strncpy(tmp, hex, 1);
		tmp[0] = 0x00;
		mpz_set_str(hldr, tmp, 16);
		dest[(i/2)+1] = 0xff & mpz_get_ui(hldr);
		for (i = 1; i < actual_len; i+=2) {
			strncpy(tmp, hex+i, 2);
			mpz_set_str(hldr, tmp, 16);
			dest[(i/2)+1] = 0xff & mpz_get_ui(hldr);
		}
	}
  mpz_clear(hldr);
}
