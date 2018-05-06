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

uint64_t cl_nonce;
uint64_t sr_nonce;

uint64_t generate_nonce()
{
	uint64_t nonce;
	RAND_bytes((unsigned char*)&nonce,8);
	return nonce;
}

int send_hello_msg(int sock) {
	hello_msg h;
	h.t = CLIENT_HELLO;
	h.nonce = cl_nonce = generate_nonce();
	convert_to_network_order(&h);
	printf("client sends nonce: %ld\n",cl_nonce);
	return send_data(sock,(unsigned char*)&h, sizeof(h));
}

int analyze_message(unsigned char* buf)
{
	convert_to_host_order(buf);
	switch( ((simple_msg*)buf)->t ) {
  		case SERVER_HELLO:
  			sr_nonce = ((hello_msg*)buf)->nonce;
  			printf("Server nonce received: %ld\n",sr_nonce);
  			break;
		default:
			return -2;
	}

	return 0;
}

unsigned int divide_upper(unsigned int dividend, unsigned int divisor)
{
    return 1 + ((dividend - 1) / divisor);
}

int main(int argc, char **argv)
{
	ERR_load_crypto_strings();

	int sd;
	uint16_t server_port;

	my_buffer my_buff;
	my_buff.buf = NULL;
	my_buff.size = 0;

	if( argc < 3 ){
		perror("use: ./client filename server_ip port");
		return -1;
	}
	sscanf(argv[3],"%hd",&server_port);

	sd = start_tcp_connection(argv[2], server_port);
	if( sd < 0 )
		return -1;
	send_hello_msg(sd);
	recv_data(sd,&my_buff);
	analyze_message(my_buff.buf);


	EncryptSession ss("keys/rsa_server_pubkey.pem");

	unsigned char *iv = ss.get_iv();
	unsigned char *session_key;
	unsigned int session_key_len = ss.get_session_key(&session_key);

	send_data(sd, session_key, session_key_len);
	send_data(sd, iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc()));

	// getting file size
	FILE *fp;
	unsigned int filesize = open_file_r(argv[1], &fp);
	unsigned int chunk_count = divide_upper(filesize, CHUNK_SIZE);
	printf("File size = %u, Chunk size = %d, Chunk count = %d\n", filesize, CHUNK_SIZE, chunk_count);

	// send to server chunk transfer details
	send_file_msg s_msg = {SEND_FILE, CHUNK_SIZE, chunk_count + 1};  // +1 for padding
	convert_to_network_order(&s_msg);
	send_data(sd, (unsigned char*)&s_msg, sizeof(s_msg));

	unsigned char datachunk[CHUNK_SIZE];
	for(unsigned int i=0; i<chunk_count; i++)
	{
		// read next chunk from file
		unsigned int chunk_plainlen = fread(datachunk, 1, CHUNK_SIZE, fp);
		printf("encrypting chunk of %d plaintext bytes\n", chunk_plainlen);

		// do encryption
		unsigned char *chunk_ciphertext;
		unsigned int chunk_cipherlen = ss.encrypt(datachunk, chunk_plainlen, &chunk_ciphertext);

		// send encrypted data
		printf("sending chunk of %d bytes\n", chunk_cipherlen);
		send_data(sd, chunk_ciphertext, chunk_cipherlen);
		delete[] chunk_ciphertext;

		// if last chunk
		if(i==chunk_count-1)
		{
			// compute padding
			unsigned char *padding_ciphertext;
			unsigned int padding_cipherlen;
			padding_cipherlen = ss.encrypt_end(&padding_ciphertext);

			// send padding
			printf("sending padding of %d bytes\n", padding_cipherlen);
			send_data(sd, padding_ciphertext, padding_cipherlen);
			delete[] padding_ciphertext;
		}
	}

	printf("session_key: ");
	print_hex(session_key, session_key_len);
	printf("iv: ");
	print_hex(iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
	//printf("ciphertext: ");
	//print_hex(ciphertext, cipherlen);

	close(sd);

	return 0;
}
