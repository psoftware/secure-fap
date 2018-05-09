#include "SignatureMaker.h"

bool SignatureMaker::read_prv_key(const char *filename)
{
	FILE* file = fopen(filename, "r");

	if(file == NULL)
		return false;

	prvkey = PEM_read_PrivateKey(file, NULL, NULL, NULL);
	if(prvkey == NULL)
		return false;

	fclose(file);
	return true;
}

SignatureMaker::SignatureMaker(const char* prvkey_path)
{
	if(!read_prv_key(prvkey_path)) {
		printf("Key read error...\n");
		return;
	}

	ctx = new EVP_MD_CTX;
	EVP_MD_CTX_init(ctx);
	EVP_SignInit(ctx, EVP_sha256());
}

unsigned int SignatureMaker::sign(unsigned char *partial_plaintext, unsigned int partial_plainlen)
{
	EVP_SignUpdate(ctx, partial_plaintext, partial_plainlen);
}

unsigned int SignatureMaker::sign_end(unsigned char **signature)
{
	*signature = new unsigned char[EVP_PKEY_size(prvkey)];
	unsigned int outlen;
	EVP_SignFinal(ctx, *signature, &outlen, prvkey);

	return outlen;
}

SignatureMaker::~SignatureMaker()
{
	EVP_MD_CTX_cleanup(ctx);
	delete ctx;
}
