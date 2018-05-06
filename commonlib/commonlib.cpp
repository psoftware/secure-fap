#include "commonlib.h"

#include <arpa/inet.h>
#include <sys/socket.h>
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


void print_hex(unsigned char* buff, unsigned int size)
{
	printf("Printing %d bytes\n", size);
	for(unsigned int i=0; i<size; i++)
		printf("%02hx", *((unsigned char*)(buff + i)));
	printf("\n");
}

unsigned int open_file_r(const char *filename, FILE **fp)
{
	unsigned int fsize;

	*fp = fopen(filename, "r");
	if(*fp) {
		fseek(*fp, 0, SEEK_END);
		fsize = ftell(*fp);
		rewind(*fp);
	}
	else {
		perror("open_file: file doesn't exist\n");
		return 0;
	}

	return fsize;
}

void open_file_w(const char *filename, FILE **fp)
{
	*fp = fopen(filename, "w");
	if(!(*fp)) {
		perror("open_file: can't create file\n");
		return;
	}
}

/* ##### OpenSSL Help Functions ##### */

unsigned int hmac_compute(unsigned char *inputdata[], unsigned int inputdata_length[], unsigned int inputdata_count, unsigned char *key, unsigned int key_length, unsigned char *hash_output)
{
	// initialize ctx
	HMAC_CTX* hmac_ctx;
	hmac_ctx = new HMAC_CTX;
	HMAC_CTX_init(hmac_ctx);

	// init HMAC (using sha256)
	HMAC_Init(hmac_ctx, key, key_length, EVP_sha256());

	// hash is based on inputdata array values concatenation
	for(unsigned int i = 0; i < inputdata_count; i++)
		HMAC_Update(hmac_ctx, inputdata[i], inputdata_length[i]);

	// finalize
	unsigned int outlen;
	HMAC_Final(hmac_ctx, hash_output, &outlen);

	// cleanup
	HMAC_CTX_cleanup(hmac_ctx);
	delete hmac_ctx;

	//NB: The HMAC_Init(), HMAC_Update(), HMAC_Final(), and HMAC_cleanup() do not return values.

	return outlen;
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

unsigned char* EncryptSession::get_iv()
{
	return iv;
}

unsigned int EncryptSession::get_session_key(unsigned char **session_key)
{
	*session_key = encrypted_keys[0];
	return encrypted_keys_len[0];
}

unsigned int EncryptSession::encrypt(unsigned char *sourcedata, unsigned int sourcedata_len, unsigned char **partial_ciphertext)
{
	*partial_ciphertext = new unsigned char[sourcedata_len];

	int outlen;
	int evp_res = EVP_SealUpdate(ctx, *partial_ciphertext, &outlen, sourcedata, sourcedata_len);
	if(evp_res == 0)
		printf("EVP_SealUpdate Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	return outlen;
}

unsigned int EncryptSession::encrypt_end(unsigned char **partial_ciphertext)
{
	// padding size is almost 16 (aes block size)
	*partial_ciphertext = new unsigned char[16];

	int outlen;
	int evp_res = EVP_SealFinal(ctx, *partial_ciphertext, &outlen);
	if(evp_res == 0)
		printf("EVP_SealFinal Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	return outlen;
}

EncryptSession::~EncryptSession()
{
	EVP_CIPHER_CTX_cleanup(ctx);
	delete ctx;

	delete[] iv;
	delete[] encrypted_keys[0];
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

unsigned int DecryptSession::decrypt(unsigned char *partial_ciphertext, unsigned int partial_cipherlen, unsigned char **partial_plaintext)
{
	*partial_plaintext = new unsigned char[partial_cipherlen + 16]; // CONTROLLARE!!!!!!

	int outlen;
	int evp_res = EVP_OpenUpdate(ctx, *partial_plaintext, &outlen, partial_ciphertext, partial_cipherlen);
	if(evp_res == 0)
		printf("EVP_OpenUpdate Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	return (unsigned int)outlen;
}

unsigned int DecryptSession::decrypt_end(unsigned char *latest_partial_plaintext)
{
	int outlen;
	int evp_res = EVP_OpenFinal(ctx, latest_partial_plaintext, &outlen);
	if(evp_res == 0)
		printf("EVP_OpenFinal Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	return (unsigned int)outlen;
}

DecryptSession::~DecryptSession()
{
	EVP_CIPHER_CTX_cleanup(ctx);
	delete ctx;
	delete prvkey;
}

SymmetricCipher::SymmetricCipher(const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv)
{
	ctx = new EVP_CIPHER_CTX;
	EVP_CIPHER_CTX_init(ctx);

	this->type = new EVP_CIPHER;
	memcpy(this->type,type,sizeof(EVP_CIPHER));
	this->key = new unsigned char[EVP_CIPHER_key_length(type)];
	memcpy(this->key,key,EVP_CIPHER_key_length(type));
	iv = new unsigned char[EVP_CIPHER_iv_length(type)];
	memcpy(this->iv,iv,EVP_CIPHER_iv_length(type));

	int evp_res = EVP_EncryptInit(ctx, this->type, this->key, this->iv);
	if(evp_res == 0)
		printf("EVP_OpenInit Error: %s\n", ERR_error_string(ERR_get_error(), NULL));
}

SymmetricCipher::~SymmetricCipher()
{
	EVP_CIPHER_CTX_cleanup(ctx);
	delete ctx;
	delete type;
	delete[] key;
	delete[] iv;
}


unsigned int SymmetricCipher::encrypt(unsigned char *sourcedata, unsigned int sourcedata_len, unsigned char **partial_ciphertext)
{
	*partial_ciphertext = new unsigned char[sourcedata_len];

	int outlen;
	int evp_res = EVP_EncryptUpdate(ctx, *partial_ciphertext, &outlen, sourcedata, sourcedata_len);
	if(evp_res == 0)
		printf("EVP_EncryptUpdate Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	return outlen;
}
unsigned int SymmetricCipher::encrypt_end(unsigned char **partial_ciphertext)
{
	// padding size is almost 16 (aes block size) 
	// controllare. Questa classe supporta diversi cipher
	*partial_ciphertext = new unsigned char[16];

	int outlen;
	int evp_res = EVP_EncryptFinal(ctx, *partial_ciphertext, &outlen);
	if(evp_res == 0)
		printf("EVP_SealFinal Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	return outlen;
}

unsigned int SymmetricCipher::decrypt(unsigned char *partial_ciphertext, unsigned int partial_cipherlen, unsigned char **partial_plaintext)
{
	// bisogna tenere conto della dimensione del blocco in base al cipher scelto
	*partial_plaintext = new unsigned char[partial_cipherlen + 16]; // CONTROLLARE!!!!!!

	int outlen;
	int evp_res = EVP_DecryptUpdate(ctx, *partial_plaintext, &outlen, partial_ciphertext, partial_cipherlen);
	if(evp_res == 0)
		printf("EVP_DecryptUpdate Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	return (unsigned int)outlen;
}

unsigned int SymmetricCipher::decrypt_end(unsigned char *latest_partial_plaintext)
{
	int outlen;
	int evp_res = EVP_DecryptFinal(ctx, latest_partial_plaintext, &outlen);
	if(evp_res == 0)
		printf("EVP_DecryptFinal Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	return (unsigned int)outlen;
}