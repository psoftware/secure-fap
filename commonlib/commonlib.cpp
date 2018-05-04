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
	free(hmac_ctx);

	//NB: The HMAC_Init(), HMAC_Update(), HMAC_Final(), and HMAC_cleanup() do not return values.

	return outlen;
}