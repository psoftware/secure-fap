#ifndef SignatureMaker_H
#define SignatureMaker_H

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

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

#endif