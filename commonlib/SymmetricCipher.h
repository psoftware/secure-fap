#ifndef SymmetricCipher_H
#define SymmetricCipher_H

#include "string.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

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
#endif