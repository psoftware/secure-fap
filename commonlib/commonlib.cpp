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