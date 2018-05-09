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