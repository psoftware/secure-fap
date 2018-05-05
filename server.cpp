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

int decrypt(
	unsigned char *encrypted_key, unsigned int encrypted_key_len,
	unsigned char *iv,
	const char *privkey_path,
	unsigned char *ciphertext, unsigned int cipherlen,
	unsigned char **plaintext)
{
	printf("encrypted_key: ");
	print_hex(encrypted_key, encrypted_key_len);
	printf("iv: ");
	print_hex(iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
	printf("ciphertext: ");
	print_hex(ciphertext, cipherlen);

	DecryptSession ds(privkey_path, encrypted_key, encrypted_key_len, iv);
	unsigned char* received_plaintext;
	unsigned int plainlen = ds.decrypt(ciphertext, cipherlen, &received_plaintext);
	printf("cipherlen %u plainlen %u\n", cipherlen, plainlen);
	plainlen += ds.decrypt_end(received_plaintext, plainlen);

	memcpy(*plaintext, received_plaintext, plainlen);

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
	ERR_load_crypto_strings();

	int err = 0;
	uint16_t server_port;
	ConnectionTCP conn;
	my_buffer my_buff;
	my_buff.buf = NULL;
	my_buff.size = 0;
	send_file_msg s_msg;

	unsigned char *encrypted_key;
	unsigned int encrypted_key_len;
	unsigned char *iv;
	unsigned int iv_len=0;

	if( argc < 2 ){
		printf("use: ./server port");
		return -1;
	}

	sscanf(argv[1],"%hd",&server_port);

	int sd = open_tcp_server(server_port);
	int cl_sd = accept_tcp_server(sd,&conn);

	recv_data(cl_sd,&my_buff); 
	analyze_message(my_buff.buf);
	send_hello_msg(cl_sd);

	//ricevo la chiave simmetrica
	encrypted_key_len = recv_data(cl_sd, &my_buff);
	encrypted_key = new unsigned char[encrypted_key_len];
	if( encrypted_key == NULL ) {
		printf("Cannot allocate encrypted_key\n");
		err = -1;
		return err;
	}
	memcpy(encrypted_key, my_buff.buf, encrypted_key_len);

	//ricevo l'iv
	iv_len = recv_data(cl_sd, &my_buff);
	iv = new unsigned char[iv_len];
	if( iv == NULL ) {
		printf("Cannot allocate iv \n");
		err = -1;
		return err;
	}

	memcpy(iv, my_buff.buf, iv_len);

	int res = recv_data(cl_sd, &my_buff);
	memcpy(&s_msg,my_buff.buf,sizeof(s_msg));
	convert_to_host_order(&s_msg);
	printf("Riceverò %d chunk di dimensione:%d \n",s_msg.chunk_number,s_msg.chunk_size);

	DecryptSession ds("keys/rsa_server_privkey.pem", encrypted_key, encrypted_key_len, iv);

	FILE *fp;
	open_file_w("ricevuto.txt", &fp);

	unsigned int total_plainlen = 0;
	// initialize receive buffer
	my_buffer chunk_cipher;
	chunk_cipher.buf = NULL;
	chunk_cipher.size = 0;
	for(unsigned int i=0; i < s_msg.chunk_number; i++)
	{
		// get chunk from tcp socket
		unsigned int chunk_cipherlen = recv_data(cl_sd, &chunk_cipher);
		printf("encrypting chunk(%d) of %d ciphertext bytes\n", s_msg.chunk_number, chunk_cipherlen);

		// do decryption
		unsigned char* chunk_plaintext;
		unsigned int chunk_plainlen = ds.decrypt(chunk_cipher.buf, chunk_cipherlen, &chunk_plaintext);
		total_plainlen += chunk_plainlen;

		// if latest chunk, compute padding
		if(i == chunk_cipherlen)
		{
			unsigned padding_plainlen = ds.decrypt_end(chunk_cipher.buf, chunk_plainlen);
			chunk_plainlen += padding_plainlen;
			total_plainlen += padding_plainlen;
		}

		fwrite(chunk_plaintext, 1, chunk_plainlen, fp);
	}
}