#include "commonlib/commonlib.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <fcntl.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <openssl/err.h>

bool read_prv_key(EVP_PKEY** prvkey)
{
	FILE* file = fopen("rsa_privkey.pem", "r");

	if(file == NULL)
		return false;

	*prvkey = PEM_read_PrivateKey(file, NULL, NULL, NULL);
	if(*prvkey == NULL)
		return false;

	fclose(file);
	return true;
}

void decrypt(int connected_client_fd)
{
	EVP_PKEY* prvkey;
	if(!read_prv_key(&prvkey))
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
}

int main()
{
	ERR_load_crypto_strings();

	printf("Starting server...\n");
	int connected_client_fd = start_server_and_wait_client("127.0.0.1", 4444);

	decrypt(connected_client_fd);
}
