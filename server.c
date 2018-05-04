#include "commonlib/net_wrapper.h"
#include "commonlib/messages.h"
#include "commonlib/commonlib.h"

#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <fcntl.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

uint64_t sr_nonce;
uint64_t cl_nonce;

uint64_t generate_nonce()
{
	uint64_t nonce;
	RAND_bytes((unsigned char*)&nonce,8);
	return nonce;
}

int send_hello_msg(int sock) {
	hello_msg h;
	h.t = SERVER_HELLO;
	h.nonce = sr_nonce = generate_nonce();
	convert_to_network_order(&h);
	printf("server sends nonce: %ld\n",sr_nonce);
	return send_data(sock,(unsigned char*)&h, sizeof(h));
}


bool read_prv_key(const char *filename, EVP_PKEY** prvkey)
{
	FILE* file = fopen(filename, "r");

	if(file == NULL)
		return false;

	*prvkey = PEM_read_PrivateKey(file, NULL, NULL, NULL);
	if(*prvkey == NULL)
		return false;

	fclose(file);
	return true;
}
/*
void decrypt_antonio(int connected_client_fd)
{
	EVP_PKEY* prvkey;
	if(!read_prv_key("keys/rsa_server_privkey.pem",&prvkey))
	{
		printf("Key read error...\n");
		return;
	}

	int encrypted_key_len;
	int rcv_len = recv_variable_string(connected_client_fd, (void*)&encrypted_key_len);
	if(rcv_len < 0)
	{
		printf("Errore recv()!\n");
		return;
	}
	printf("encrypted_key_len (rcv_len = %d) = %u\n\n", rcv_len, encrypted_key_len);

	unsigned char *encrypted_key = malloc(encrypted_key_len);
	int key_rcv_len = recv_variable_string(connected_client_fd, encrypted_key);
	if(key_rcv_len < 0)
	{
		printf("Errore recv()!\n");
		return;
	}
	printf("encrypted_key (key_rcv_len = %d) = ..\n\n", key_rcv_len);
	print_hex(encrypted_key, key_rcv_len);

	char *iv = malloc(EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
	int iv_len = recv_variable_string(connected_client_fd, iv);
	if(iv_len < 0)
	{
		printf("Errore recv()!\n");
		return;
	}
	printf("iv (iv_len = %d) = ..\n\n", iv_len);
	print_hex(iv, iv_len);

	char *ciphertext = malloc(5000);
	if(!ciphertext){ printf("Errore allocazione ciphertext!\n"); return;}

	int cipherlen = recv_variable_string(connected_client_fd, ciphertext);
	if(cipherlen < 0)
	{
		printf("Errore recv()!\n");
		return;
	}
	printf("ciphertext (cipherlen = %d) = ..\n", cipherlen);

	unsigned char* plaintext = malloc(cipherlen);
	if(!plaintext){ printf("Errore allocazione plaintext!\n"); return;}
	int outlen, plainlen;

	EVP_CIPHER_CTX* ctx = malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);

	int evp_res = EVP_OpenInit(ctx, EVP_aes_128_cbc(),
					encrypted_key, encrypted_key_len, iv, prvkey);
	if(evp_res == 0)
		printf("EVP_OpenInit Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	evp_res = EVP_OpenUpdate(ctx, plaintext, &outlen, ciphertext, cipherlen);
	if(evp_res == 0)
		printf("EVP_OpenUpdate Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	plainlen = outlen;

	evp_res = EVP_OpenFinal(ctx, plaintext + plainlen, &outlen);
	if(evp_res == 0)
		printf("EVP_OpenUpdate Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	plainlen += outlen;

	printf("Text: %s\n", plaintext);
}*/

int decrypt(unsigned char *encrypted_key, 
	unsigned int encrypted_key_len, 
	unsigned char *iv, 
	EVP_PKEY *privkey, 
	unsigned char *ciphertext, 
	unsigned int cipherlen, 
	unsigned char **plaintext)
{
	EVP_CIPHER_CTX *ctx = malloc(sizeof(EVP_CIPHER_CTX));
	if( ctx == NULL ){
		printf("Error allocate EVP_CIPHER_CTX \n");
		return 0;
	}
	
	int outlen = 0, plainlen = 0;
	int evp_res = EVP_OpenInit(ctx, EVP_aes_128_cbc(), encrypted_key, encrypted_key_len, iv, privkey);
	if(evp_res == 0) {
		printf("EVP_OpenInit Error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return 0;
	}

	evp_res = EVP_OpenUpdate(ctx, *plaintext, &outlen, ciphertext, cipherlen);
	if(evp_res == 0) {
		printf("EVP_OpenUpdate Error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return 0;
	}
	
	plainlen = outlen;
	evp_res = EVP_OpenFinal(ctx, *plaintext + plainlen, &outlen);
	if(evp_res == 0) {
		printf("EVP_OpenFinal Error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return 0;
	}

	plainlen += outlen;

	EVP_CIPHER_CTX_cleanup(ctx);
	free(ctx);

	return plainlen;
}

int analyze_message(unsigned char* buf)
{
	convert_to_host_order(buf);
 	switch( ((simple_msg*)buf)->t ) {
  		case CLIENT_HELLO:
  			cl_nonce = ((hello_msg*)buf)->nonce;
  			printf("Client nonce received: %ld\n",cl_nonce);
  			break;
		default:
			return -2;
	}

	return 0;
}
int main(int argc, char** argv)
{
	int err = 0;
	uint16_t server_port;
	ConnectionTCP conn;
	my_buffer my_buff;
	my_buff.buf = NULL;
	my_buff.size = 0;

	unsigned char *plaintext;
	unsigned char *encrypted_key;
	unsigned int encrypted_key_len;
	unsigned char *iv;
	unsigned char *ciphertext;
	unsigned int cipherlen=0, iv_len=0;
	EVP_PKEY *privkey;

	if( argc < 2 ){
		printf("use: ./server port");
		return -1;
	}

	sscanf(argv[1],"%hd",&server_port);

	
	bool r = read_prv_key("keys/rsa_server_privkey.pem", &privkey);
	if( !r ){
		printf("Errore lettura chiave privata\n");
		return -1;
	}

	int sd = open_serverTCP(server_port);
	int cl_sd = accept_serverTCP(sd,&conn);

	recv_data(cl_sd,&my_buff); 
	analyze_message(my_buff.buf);
	send_hello_msg(cl_sd);

	//ricevo la chiave simmetrica
	encrypted_key_len = recv_data(cl_sd, &my_buff);
	encrypted_key = malloc(encrypted_key_len);
	if( encrypted_key == NULL ) {
		printf("Cannot allocate encrypted_key\n");
		err = -1;
		goto finalize;
	}
	memcpy(encrypted_key, my_buff.buf, encrypted_key_len);

	//ricevo l'iv
	iv_len = recv_data(cl_sd, &my_buff);
	iv = malloc(iv_len);
	if( iv == NULL ) {
		printf("Cannot allocate iv \n");
		err = -1;
		goto finalize;
	}

	memcpy(iv, my_buff.buf, iv_len);

	//ricevo il ciphertext
	cipherlen = recv_data(cl_sd, &my_buff);
	ciphertext = malloc(cipherlen);
	if( ciphertext == NULL ) {
		printf("Cannot allocate ciphertext \n");
		err = -1;
		goto finalize;
	}
	memcpy(ciphertext, my_buff.buf, cipherlen);

//	printf("Alloco plaintext di %d byte \n",ciph_len);
	plaintext = malloc(cipherlen);
	if( plaintext == NULL ) {
		printf("Cannot allocate plaintext \n");
		err = -1;
		goto finalize;
	}

	decrypt(encrypted_key,encrypted_key_len,iv,privkey,ciphertext,cipherlen,&plaintext);

	//printf("plaintext:%s\n",plaintext);

finalize:
	close(cl_sd);
	close(sd);

	return err;
}