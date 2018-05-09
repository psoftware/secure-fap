#include "SignatureVerifier.h"

bool SignatureVerifier::read_pub_key(const char *filename)
{
	FILE* file = fopen(filename, "r");

	if(file == NULL)
		return false;

	pubkeys[0] = PEM_read_PUBKEY(file, NULL, NULL, NULL);
	if(pubkeys[0] == NULL)
		return false;

	fclose(file);
		return true;
}

SignatureVerifier::SignatureVerifier(const char* pubkey_path)
{
	if(!read_pub_key(pubkey_path)) {
		printf("Key read error...\n");
		return;
	}

	ctx = new EVP_MD_CTX;
	EVP_MD_CTX_init(ctx);
	EVP_VerifyInit(ctx, EVP_sha256());
}

void SignatureVerifier::verify(unsigned char *partial_plaintext, unsigned int partial_plainlen)
{
	EVP_VerifyUpdate(ctx, partial_plaintext, partial_plainlen);
}

bool SignatureVerifier::verify_end(unsigned char *signature, unsigned int signature_len)
{
	int res = EVP_VerifyFinal(ctx, signature, signature_len, pubkeys[0]);
	if(res != 1)
		return false;

	return true;
}

SignatureVerifier::~SignatureVerifier()
{
	EVP_MD_CTX_cleanup(ctx);
	delete ctx;
}
