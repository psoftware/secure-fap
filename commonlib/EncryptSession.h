#ifndef EncryptSession_H
#define EncryptSession_H
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "messages.h"
#include "DynamicArray.h"

class EncryptSession {
private:
	EVP_PKEY* pubkeys[1];

	EVP_CIPHER_CTX* ctx;
	unsigned char *iv;
	unsigned char *encrypted_keys[1];
	int encrypted_keys_len[1];

	DynamicArray ciphertext;

	bool read_pub_key(const char *filename);
	EncryptSession(const EncryptSession&);
public:
	EncryptSession(const char* pubkey_path);

	unsigned char *get_iv();
	unsigned int get_session_key(unsigned char **session_key);

	unsigned int encrypt(unsigned char *sourcedata, unsigned int sourcedata_len);
	unsigned int encrypt_end();
	unsigned int flush_ciphertext(unsigned char **ciphertext);

	~EncryptSession();
};
#endif