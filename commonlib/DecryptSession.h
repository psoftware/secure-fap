#ifndef DecryptSession_H
#define DecryptSession_H

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

#endif