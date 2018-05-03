#include "net_wrapper.h"
#include "commonlib/commonlib.h"

#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <fcntl.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <openssl/err.h>

bool read_pub_key(EVP_PKEY** pubkeys)
{
        //EVP_PKEY* pubkeys[1];
        FILE* file = fopen("keys/rsa_server_pubkey.pem", "r");

        if(file == NULL)
                return false;

        pubkeys[0] = PEM_read_PUBKEY(file, NULL, NULL, NULL);
        if(pubkeys[0] == NULL)
                return false;

        fclose(file);
        return true;
}

unsigned int readcontent(const char *filename, unsigned char** fcontent)
{
	unsigned int fsize = 0;
	FILE *fp;

	fp = fopen(filename, "r");
	if(fp) {
		fseek(fp, 0, SEEK_END);
		fsize = ftell(fp);
		rewind(fp);

		//printf("fsize is %u \n",fsize);
		*fcontent = (unsigned char*) malloc(sizeof(char) * fsize + 1);
		fread(*fcontent, 1, fsize, fp);
		(*fcontent)[fsize] = '\0';

		fclose(fp);
	} else {
		perror("file doesn't exist \n");
		return 0;
	}
	return fsize + 1;
}



void encrypt_antonio(int cl_sock)
{
	EVP_PKEY* pubkeys[1];
	if(!read_pub_key(pubkeys))
	{
		printf("Key read error...\n");
		return;
	}

	char msg[] = "MERDA 123456789.";
	unsigned char* encrypted_keys[1];
	int encrypted_keys_len[1];
	encrypted_keys_len[0] = EVP_PKEY_size(pubkeys[0]);
	encrypted_keys[0] = malloc(encrypted_keys_len[0]);

	unsigned char* ciphertext = malloc(sizeof(msg) + 16);
	int outlen, cipherlen;

	EVP_CIPHER_CTX* ctx = malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);

	void *iv = malloc(EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
	int evp_res = EVP_SealInit(ctx, EVP_aes_128_cbc(),
		encrypted_keys, encrypted_keys_len, iv, pubkeys, 1);
	if(evp_res == 0)
		printf("EVP_SealInit Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	evp_res = EVP_SealUpdate(ctx, ciphertext, &outlen, (unsigned char*)msg, sizeof(msg));
	if(evp_res == 0)
		printf("EVP_SealUpdate Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	cipherlen = outlen;

	evp_res = EVP_SealFinal(ctx, ciphertext + cipherlen, &outlen);
	if(evp_res == 0)
		printf("EVP_SealFinal Error: %s\n", ERR_error_string(ERR_get_error(), NULL));

	cipherlen += outlen;

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

	EVP_CIPHER_CTX_cleanup(ctx);
	free(ctx);
}

int main(int argc, char **argv) {
	uint16_t server_port;

	ERR_load_crypto_strings();

	if( argc < 3 ){
		perror("use: ./client filename server_ip port");
		return -1;
	}


	sscanf(argv[3],"%hd",&server_port);
	printf("Mi connetto...\n");
	int sock_client = start_tcp_connection(argv[2], server_port);
	printf("Connessione riuscita!\n");

	printf("Invio file...!\n");
	encrypt_antonio(sock_client);
	printf("Invio file completato!\n");
}
