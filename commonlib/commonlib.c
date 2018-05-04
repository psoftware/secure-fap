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
	hmac_ctx = malloc(sizeof(HMAC_CTX));
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

// to remove

int recv_variable_string(int cl_sock, unsigned char * buff)
{
	//faccio una recv di un byte
	unsigned int bytes_count;
	int ret = recv(cl_sock, (void*)&bytes_count, sizeof(unsigned int), MSG_WAITALL);
	if(ret == 0 || ret == -1)
		return ret;

	bytes_count=ntohl(bytes_count);

	//faccio una recv di nbyte ricevuti dalla recv precedente
	ret = recv(cl_sock, (void*)buff, bytes_count, MSG_WAITALL);
	if(ret == 0 || ret == -1)
		return ret;
	if(ret < bytes_count)
	{
		printf("recv_variable_string: Byte ricevuti (%d) minori di quelli previsti!\n", ret);
		return -1;
	}

	//print_hex(buff, bytes_count);

	return bytes_count;
}

int send_variable_string(int cl_sock, unsigned char * buff, int bytes_count)
{
	//faccio una send del numero di byte che devo spedire
	int net_bytes_count = htonl(bytes_count);
	int ret = send(cl_sock, (unsigned int*)&net_bytes_count, sizeof(unsigned int), 0);
	if(ret == 0 || ret == -1)
		return ret;

	//faccio una send per i bytes_count bytes da inviare
	ret = send(cl_sock, (void*)buff, bytes_count, 0);
	if(ret == 0 || ret == -1)
		return ret;
	if(ret < bytes_count)
	{
		printf("send_variable_string: Byte ricevuti (%d) minori di quelli previsti!\n", ret);
		return -1;
	}

	//print_hex(buff, bytes_count);

	return ret;
}