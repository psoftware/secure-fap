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

HMACMaker::HMACMaker(unsigned char *key, unsigned int key_length)
{
	hmac_ctx = new HMAC_CTX;
	HMAC_CTX_init(hmac_ctx);

	// init HMAC (using sha256)
	HMAC_Init(hmac_ctx, key, key_length, EVP_sha256());
}

unsigned int HMACMaker::hash(unsigned char *partial_plaintext, unsigned int partial_plainlen)
{
	HMAC_Update(hmac_ctx, partial_plaintext, partial_plainlen);
}

unsigned int HMACMaker::hash_end(unsigned char **hash)
{
	*hash = new unsigned char[HMAC_LENGTH];
	unsigned int outlen;
	HMAC_Final(hmac_ctx, *hash, &outlen);

	return outlen;
}

HMACMaker::~HMACMaker()
{
	HMAC_CTX_cleanup(hmac_ctx);
	delete hmac_ctx;
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


unsigned int SymmetricCipher::encrypt(unsigned char *sourcedata, unsigned int sourcedata_len, unsigned char **partial_ciphertext)
{
	*partial_ciphertext = new unsigned char[sourcedata_len];

	int outlen;
	int evp_res = EVP_EncryptUpdate(encrypt_ctx, *partial_ciphertext, &outlen, sourcedata, sourcedata_len);
	if(evp_res == 0)
		printf("EVP_EncryptUpdate Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	return outlen;
}
unsigned int SymmetricCipher::encrypt_end(unsigned char **partial_ciphertext)
{
	// padding size is almost 16 (aes block size) 
	// controllare. Questa classe supporta diversi cipher
	*partial_ciphertext = new unsigned char[EVP_CIPHER_block_size(type)];

	int outlen;
	int evp_res = EVP_EncryptFinal(encrypt_ctx, *partial_ciphertext, &outlen);
	if(evp_res == 0)
		printf("EVP_EncryptFinal Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	return outlen;
}

unsigned int SymmetricCipher::decrypt(unsigned char *partial_ciphertext, unsigned int partial_cipherlen, unsigned char **partial_plaintext)
{
	// bisogna tenere conto della dimensione del blocco in base al cipher scelto
	*partial_plaintext = new unsigned char[partial_cipherlen + EVP_CIPHER_block_size(type)]; // CONTROLLARE!!!!!!

	int outlen;
	int evp_res = EVP_DecryptUpdate(decrypt_ctx, *partial_plaintext, &outlen, partial_ciphertext, partial_cipherlen);
	if(evp_res == 0)
		printf("EVP_DecryptUpdate Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	return (unsigned int)outlen;
}

unsigned int SymmetricCipher::decrypt_end(unsigned char *latest_partial_plaintext)
{
	int outlen;
	int evp_res = EVP_DecryptFinal(decrypt_ctx, latest_partial_plaintext, &outlen);
	if(evp_res == 0)
		printf("EVP_DecryptFinal Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	return (unsigned int)outlen;
}

unsigned char* SymmetricCipher::get_iv()
{
	return this->iv;
}

unsigned char* SymmetricCipher::get_key()
{
	return this->key;
}

bool recv_msg(int sd, void *s_msg, message_type expected)
{
	my_buffer my_buff = {NULL, 0};
	int bytes_rec = recv_data(sd, &my_buff);
	memcpy(s_msg,my_buff.buf,bytes_rec);
	int t = convert_to_host_order(s_msg);
	printf("expected:%d received:%d \n",expected,t);
	if( t == expected )
		return true;
	else 
		return false;
}