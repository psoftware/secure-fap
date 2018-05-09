#include "SymmetricCipher.h"

SymmetricCipher::SymmetricCipher(const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv) : iv(NULL)
{
	encrypt_ctx = new EVP_CIPHER_CTX;
	EVP_CIPHER_CTX_init(encrypt_ctx);
	decrypt_ctx = new EVP_CIPHER_CTX;
	EVP_CIPHER_CTX_init(decrypt_ctx);

	this->type = new EVP_CIPHER;
	memcpy(this->type,type,sizeof(EVP_CIPHER));
	this->key = new unsigned char[EVP_CIPHER_key_length(type)];
	memcpy(this->key,key,EVP_CIPHER_key_length(type));

	//printf("key_length:%d \n",EVP_CIPHER_key_length(type));

	if( iv != NULL) {
		this->iv = new unsigned char[EVP_CIPHER_iv_length(type)];
		memcpy(this->iv,iv,EVP_CIPHER_iv_length(type));
	}

	int evp_res = EVP_EncryptInit(encrypt_ctx, this->type, this->key, this->iv);
	if(evp_res == 0)
		printf("EVP_EncryptInit Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	evp_res = EVP_DecryptInit(decrypt_ctx, this->type, this->key, this->iv);
	if(evp_res == 0)
		printf("EVP_DecryptInit Error: %s\n", ERR_error_string(ERR_get_error(), NULL));
}

SymmetricCipher::~SymmetricCipher()
{
	EVP_CIPHER_CTX_cleanup(encrypt_ctx);
	EVP_CIPHER_CTX_cleanup(decrypt_ctx);
	delete encrypt_ctx;
	delete decrypt_ctx;
	delete type;
	delete[] key;
	delete[] iv;
}


unsigned int SymmetricCipher::encrypt(unsigned char *sourcedata, unsigned int sourcedata_len)
{
	unsigned char *partial_ciphertext = new unsigned char[sourcedata_len];

	int outlen;
	int evp_res = EVP_EncryptUpdate(encrypt_ctx, partial_ciphertext, &outlen, sourcedata, sourcedata_len);
	if(evp_res == 0)
		printf("EVP_EncryptUpdate Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	this->ciphertext.appendBytes(partial_ciphertext, outlen);
	delete[] partial_ciphertext;

	return outlen;
}
unsigned int SymmetricCipher::encrypt_end()
{
	// padding size is almost 16 (aes block size) 
	// controllare. Questa classe supporta diversi cipher
	unsigned char *partial_ciphertext = new unsigned char[EVP_CIPHER_block_size(type)];

	int outlen;
	int evp_res = EVP_EncryptFinal(encrypt_ctx, partial_ciphertext, &outlen);
	if(evp_res == 0)
		printf("EVP_EncryptFinal Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	this->ciphertext.appendBytes(partial_ciphertext, outlen);
	delete[] partial_ciphertext;

	return outlen;
}

unsigned int SymmetricCipher::decrypt(unsigned char *partial_ciphertext, unsigned int partial_cipherlen)
{
	// bisogna tenere conto della dimensione del blocco in base al cipher scelto
	unsigned char *partial_plaintext = new unsigned char[partial_cipherlen + EVP_CIPHER_block_size(type)]; // CONTROLLARE!!!!!!

	int outlen;
	int evp_res = EVP_DecryptUpdate(decrypt_ctx, partial_plaintext, &outlen, partial_ciphertext, partial_cipherlen);
	if(evp_res == 0)
		printf("EVP_DecryptUpdate Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	this->plaintext.appendBytes(partial_plaintext, outlen);
	delete[] partial_plaintext;

	return (unsigned int)outlen;
}

unsigned int SymmetricCipher::decrypt_end()
{
	unsigned char *partial_plaintext = new unsigned char[16];
	int outlen;
	int evp_res = EVP_DecryptFinal(decrypt_ctx, partial_plaintext, &outlen);
	if(evp_res == 0)
		printf("EVP_DecryptFinal Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	this->plaintext.appendBytes(partial_plaintext, outlen);
	delete[] partial_plaintext;

	return (unsigned int)outlen;
}

unsigned int SymmetricCipher::flush_ciphertext(unsigned char **ciphertext)
{
	int size = this->ciphertext.getLength();
	*ciphertext = this->ciphertext.detachArray();
	return size;
}

unsigned int SymmetricCipher::flush_plaintext(unsigned char **plaintext)
{
	int size = this->plaintext.getLength();
	*plaintext = this->plaintext.detachArray();
	return size;
}

unsigned char* SymmetricCipher::get_key()
{
	return this->key;
}