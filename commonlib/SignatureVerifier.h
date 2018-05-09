#ifndef SignatureVerifier_H
#define SignatureVerifier_H

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>


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
#endif