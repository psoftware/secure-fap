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
	free(ctx);

	delete iv;
	delete encrypted_keys[0];
}

/*
	print_hex((void*)(&encrypted_keys[0][0]), encrypted_keys_len[0]);
	print_hex(iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc()));

	// dobbiamo trasmettere encrypted keys e iv
	if(send_variable_string(cl_sock, (void*)&encrypted_keys_len[0], sizeof(encrypted_keys_len[0])) < 0)
		printf("Errore send_variable_string()!\n");
	if(send_variable_string(cl_sock, (void*)(&encrypted_keys[0][0]), encrypted_keys_len[0]) < 0)
		printf("Errore send_variable_string()!\n");
	if(send_variable_string(cl_sock, iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc())) < 0)
		printf("Errore send_variable_string()!\n");
	if(send_variable_string(cl_sock, ciphertext, cipherlen) < 0)
		printf("Errore send_variable_string()!\n");
*/

/* OBSOLETE*/
int initialize_server_socket(const char * bind_addr, int port)
{
	int ret_sock = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in my_addr;
	memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(port);
	inet_pton(AF_INET, bind_addr, &my_addr.sin_addr);

	if(bind(ret_sock, (struct sockaddr*)&my_addr, sizeof(my_addr)) == -1)
	{
		printf("Error %s\n", strerror(errno));
		return -1;
	}
	if(listen(ret_sock, 10) == -1)
	{
		printf("Error %s\n", strerror(errno));
		return -2;
	}

	return ret_sock;
}

int start_server_and_wait_client(const char* ip_addr, int port)
{
	int server_socket = initialize_server_socket(ip_addr, port);
	if(server_socket < 0)
	{
		printf("Error %s\n", strerror(errno));
		return 1;
	}

	printf("start_server: server in ascolto su %s:%d\n", ip_addr, port);

	// dobbiamo aspettare che il client si connetta
	struct sockaddr_in cl_addr;
	int my_len = sizeof(cl_addr);
	int connected_client_fd = accept(server_socket, (struct sockaddr*)&cl_addr, (socklen_t*)&my_len);
	printf("start_server: client connesso!\n");

	return connected_client_fd;
}

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