#include "EncryptSession.h"

EncryptSession::EncryptSession(const char* pubkey_path) {
	if(!read_pub_key(pubkey_path)) {
		printf("Key read error...\n");
		return;
	}

	ctx = new EVP_CIPHER_CTX;
	EVP_CIPHER_CTX_init(ctx);

	iv = new unsigned char[EVP_CIPHER_iv_length(EVP_aes_128_cbc())];
	encrypted_keys_len[0] = EVP_PKEY_size(pubkeys[0]);
	encrypted_keys[0] = new unsigned char[encrypted_keys_len[0]];

	int evp_res = EVP_SealInit(ctx, EVP_aes_128_cbc(), encrypted_keys, encrypted_keys_len, iv, pubkeys, 1);
	if(evp_res == 0)
		printf("EVP_SealInit Error: %s\n", ERR_error_string(ERR_get_error(), NULL));
}

bool EncryptSession::read_pub_key(const char *filename)
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


unsigned char* EncryptSession::get_iv()
{
	return iv;
}

unsigned int EncryptSession::get_session_key(unsigned char **session_key)
{
	*session_key = encrypted_keys[0];
	return encrypted_keys_len[0];
}

unsigned int EncryptSession::encrypt(unsigned char *sourcedata, unsigned int sourcedata_len)
{
	unsigned char *partial_ciphertext = new unsigned char[sourcedata_len + 16]; //CONTROLLARE!

	int outlen;
	int evp_res = EVP_SealUpdate(ctx, partial_ciphertext, &outlen, sourcedata, sourcedata_len);
	if(evp_res == 0)
		printf("EVP_SealUpdate Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	this->ciphertext.appendBytes(partial_ciphertext, outlen);
	delete[] partial_ciphertext;

	return outlen;
}

unsigned int EncryptSession::encrypt_end()
{
	// padding size is almost 16 (aes block size)
	unsigned char *partial_ciphertext = new unsigned char[16];

	int outlen;
	int evp_res = EVP_SealFinal(ctx, partial_ciphertext, &outlen);
	if(evp_res == 0)
		printf("EVP_SealFinal Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	this->ciphertext.appendBytes(partial_ciphertext, outlen);
	delete[] partial_ciphertext;

	return outlen;
}

unsigned int EncryptSession::flush_ciphertext(unsigned char **ciphertext)
{
	int size = this->ciphertext.getLength();
	*ciphertext = this->ciphertext.detachArray();
	return size;
}

EncryptSession::~EncryptSession()
{
	EVP_CIPHER_CTX_cleanup(ctx);
	delete ctx;

	delete[] iv;
	EVP_PKEY_free(pubkeys[0]);
}