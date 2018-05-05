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
		*fcontent = new unsigned char[fsize + 1];
		fread(*fcontent, 1, fsize, fp);
		(*fcontent)[fsize] = '\0';

		fclose(fp);
	} else {
		perror("file doesn't exist \n");
		return 0;
	}
	return fsize + 1;
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

int main(int argc, char **argv)
{
	ERR_load_crypto_strings();

	int sd;
	unsigned char *buffer_file = NULL;
	unsigned int file_len = 0;
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

	// leggo l contenuto del file da inviare
	file_len = readcontent(argv[1],&buffer_file);

	EncryptSession ss("keys/rsa_server_pubkey.pem");

	unsigned char *iv = ss.get_iv();
	unsigned char *session_key;
	unsigned int session_key_len = ss.get_session_key(&session_key);

	send_data(sd, session_key, session_key_len);
	send_data(sd, iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc()));

	unsigned char *ciphertext = new unsigned char[file_len + 16];
	unsigned char *partial_ciphertext;
	unsigned int cipherlen = ss.encrypt(buffer_file, file_len, &partial_ciphertext);
	memcpy(ciphertext, partial_ciphertext, cipherlen);
	delete partial_ciphertext;

	int outlen = ss.encrypt_end(&partial_ciphertext);
	memcpy(ciphertext + cipherlen, partial_ciphertext, outlen);
	cipherlen += outlen;
	delete partial_ciphertext;


	send_file_msg s_msg = {SEND_FILE, cipherlen, 1};
	printf("Manderò %d chunk di dimensione:%d \n",s_msg.chunk_number,s_msg.chunk_size);
	convert_to_network_order(&s_msg);
	send_data(sd, (unsigned char*)&s_msg, sizeof(s_msg));
	send_data(sd, ciphertext, cipherlen);

	printf("session_key: ");
	print_hex(session_key, session_key_len);
	printf("iv: ");
	print_hex(iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
	printf("ciphertext: ");
	print_hex(ciphertext, cipherlen);

	close(sd);

	return 0;
}
