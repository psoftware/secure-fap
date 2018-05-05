#ifndef __COMMONLIB
#define __COMMONLIB

#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <fcntl.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define HMAC_LENGTH 32


/* ##### OpenSSL Help Functions ##### */
unsigned int hmac_compute(
	unsigned char *inputdata[], unsigned int inputdata_length[], unsigned int inputdata_count,
	unsigned char *key, unsigned int key_length,
	unsigned char *hash_output);

class EncryptSession {
private:
	EVP_PKEY* pubkeys[1];

	EVP_CIPHER_CTX* ctx;
	unsigned char *iv;
	unsigned char *encrypted_keys[1];
	int encrypted_keys_len[1];

	bool read_pub_key(const char *filename);

public:
	EncryptSession(const char* pubkey_path);

	unsigned char *get_iv();
	unsigned int get_session_key(unsigned char **session_key);

	unsigned int encrypt(unsigned char *sourcedata, unsigned int sourcedata_len, unsigned char **partial_ciphertext);
	unsigned int encrypt_end(unsigned char **partial_ciphertext);

	~EncryptSession();
};

// Utils
void print_hex(unsigned char* buff, unsigned int size);

// Server functions
int initialize_server_socket(const char * bind_addr, int port);

#endif