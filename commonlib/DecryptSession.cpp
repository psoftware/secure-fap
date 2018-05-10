#include "DecryptSession.h"

DecryptSession::DecryptSession(const char* prvkey_path, unsigned char *session_key, unsigned int session_key_len, unsigned char *iv) {
	//"keys/rsa_server_privkey.pem"
	if(!read_prv_key(prvkey_path)) {
		printf("Key read error...\n");
		return;
	}

	ctx = new EVP_CIPHER_CTX;
	EVP_CIPHER_CTX_init(ctx);

	int evp_res = EVP_OpenInit(ctx, EVP_aes_128_cbc(), session_key, session_key_len, iv, prvkey);
	if(evp_res == 0)
		printf("EVP_OpenInit Error: %s\n", ERR_error_string(ERR_get_error(), NULL));
}

bool DecryptSession::read_prv_key(const char *filename)
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

unsigned int DecryptSession::decrypt(unsigned char *partial_ciphertext, unsigned int partial_cipherlen)
{
	unsigned char *partial_plaintext = new unsigned char[partial_cipherlen + 16]; // CONTROLLARE!!!!!!

	int outlen;
	int evp_res = EVP_OpenUpdate(ctx, partial_plaintext, &outlen, partial_ciphertext, partial_cipherlen);
	if(evp_res == 0)
		printf("EVP_OpenUpdate Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	this->plaintext.appendBytes(partial_plaintext, outlen);
	delete[] partial_plaintext;

	return (unsigned int)outlen;
}

unsigned int DecryptSession::decrypt_end()
{
	unsigned char *latest_partial_plaintext = new unsigned char[16];
	int outlen;
	int evp_res = EVP_OpenFinal(ctx, latest_partial_plaintext, &outlen);
	if(evp_res == 0)
		printf("EVP_OpenFinal Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	this->plaintext.appendBytes(latest_partial_plaintext, outlen);
	delete[] latest_partial_plaintext;

	return (unsigned int)outlen;
}

unsigned int DecryptSession::flush_plaintext(unsigned char **plaintext)
{
	int size = this->plaintext.getLength();
	*plaintext = this->plaintext.detachArray();
	return size;
}

DecryptSession::~DecryptSession()
{
	EVP_CIPHER_CTX_cleanup(ctx);
	delete ctx;
	EVP_PKEY_free(prvkey);
}