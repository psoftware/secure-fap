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
#include "messages.h"
#include "net_wrapper.h"

#define CHUNK_SIZE 32
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
	EncryptSession(const EncryptSession&);
public:
	EncryptSession(const char* pubkey_path);

	unsigned char *get_iv();
	unsigned int get_session_key(unsigned char **session_key);

	unsigned int encrypt(unsigned char *sourcedata, unsigned int sourcedata_len, unsigned char **partial_ciphertext);
	unsigned int encrypt_end(unsigned char **partial_ciphertext);

	~EncryptSession();
};

class DecryptSession {
private:
	EVP_PKEY* prvkey;

	EVP_CIPHER_CTX* ctx;

	bool read_prv_key(const char *filename);
	DecryptSession(const DecryptSession&);
public:
	DecryptSession(const char* prvkey_path, unsigned char *encrypted_key, unsigned int encrypted_key_len, unsigned char *iv);

	unsigned int decrypt(unsigned char *partial_ciphertext, unsigned int partial_cipherlen, unsigned char **partial_plaintext);
	unsigned int decrypt_end(unsigned char *latest_partial_plaintext);

	~DecryptSession();
};

class SignatureMaker {
private:
	EVP_PKEY* prvkey;

	EVP_MD_CTX* ctx;

	bool read_prv_key(const char *filename);
	SignatureMaker(const SignatureMaker&);
public:
	SignatureMaker(const char* prvkey_path);

	unsigned int sign(unsigned char *partial_plaintext, unsigned int partial_plainlen);
	unsigned int sign_end(unsigned char **signature);

	~SignatureMaker();
};

class SignatureVerifier {
private:
	EVP_PKEY* pubkeys[1];

	EVP_MD_CTX* ctx;

	bool read_pub_key(const char *filename);
	SignatureVerifier(const SignatureVerifier&);
public:
	SignatureVerifier(const char* pubkey_path);

	void verify(unsigned char *partial_plaintext, unsigned int partial_plainlen);
	bool verify_end(unsigned char *signature, unsigned int signature_len);

	~SignatureVerifier();
};


class SymmetricCipher {
private:
	EVP_CIPHER_CTX* encrypt_ctx;
	EVP_CIPHER_CTX* decrypt_ctx;
	EVP_CIPHER *type;
	unsigned char *key;
	unsigned char *iv;
	SymmetricCipher(const SymmetricCipher&);
public:
	SymmetricCipher(const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv);
	~SymmetricCipher();

	unsigned char* get_iv();
	unsigned char* get_key();
	unsigned int encrypt(unsigned char *sourcedata, unsigned int sourcedata_len, unsigned char **partial_ciphertext);
	unsigned int encrypt_end(unsigned char **partial_ciphertext);
	unsigned int decrypt(unsigned char *partial_ciphertext, unsigned int partial_cipherlen, unsigned char **partial_plaintext);
	unsigned int decrypt_end(unsigned char *latest_partial_plaintext);
};

// Utils
void print_hex(unsigned char* buff, unsigned int size);

unsigned int open_file_r(const char *filename, FILE **fp);
void open_file_w(const char *filename, FILE **fp);

// Server functions
int initialize_server_socket(const char * bind_addr, int port);

bool recv_msg(int sd, void *s_msg, message_type expected);

#endif