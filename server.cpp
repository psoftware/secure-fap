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

bool send_hello_msg(int sock) {
	hello_msg h;
	h.t = SERVER_HELLO;
	h.nonce = sr_nonce = generate_nonce();
	convert_to_network_order(&h);
	printf("server sends nonce: %ld\n",sr_nonce);
	if( send_data(sock,(unsigned char*)&h, sizeof(h)) == sizeof(h) )
		return true;
	else
		return false;

}

bool recv_hello_msg(int sd){
	hello_msg h_msg;
	if(	!recv_msg(sd, &h_msg ,CLIENT_HELLO) )
	{
		printf("Error receive CLIENT_HELLO\n");
		return false;
	} else  {
		cl_nonce = h_msg.nonce;
		return true;
	}
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

	// 1) Get Client Nonce
	if( !recv_hello_msg(cl_sd) )
		return -1;

	// 2) Send Server Nonce
	if ( !send_hello_msg(cl_sd) )
		return -1;

	// 3) Send Server verification infos
	// VA FATTO CON LA FIRMA DIGITALE

	// 4) Validate Client and Get Session key
	// getting session encrypted key
	unsigned int auth_encrypted_key_len = recv_data(cl_sd, &my_buff);
	if(auth_encrypted_key_len > 10000)
	{
		printf("error: auth_encrypted_key_len = %u invalid size!\n", auth_encrypted_key_len);
		return -1;
	}
	unsigned char *auth_encrypted_key = new unsigned char[auth_encrypted_key_len];
	memcpy(auth_encrypted_key, my_buff.buf, auth_encrypted_key_len);

	// getting session iv
	unsigned char *auth_iv = new unsigned char[EVP_CIPHER_iv_length(EVP_aes_128_cbc())];
	unsigned int auth_iv_len = recv_data(cl_sd, &my_buff);
	if((int)auth_iv_len != EVP_CIPHER_iv_length(EVP_aes_128_cbc())) {
		printf("error: auth_iv_len = %u instead of %d!\n", auth_iv_len, EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
		return -1;
	}
	memcpy(auth_iv, my_buff.buf, auth_iv_len);


	// getting client authentication header
	client_auth auth_header_msg;
	recv_data(cl_sd, &my_buff);
	memcpy(&auth_header_msg, my_buff.buf, sizeof(auth_header_msg));
	convert_to_host_order(&auth_header_msg);

	printf("client header: ciphertext_len = %u, username_length = %u, password_length = %u\n",
		auth_header_msg.total_ciphertext_size, auth_header_msg.username_length, auth_header_msg.password_length);

	DecryptSession asymm_authclient_decipher("keys/rsa_server_privkey.pem", auth_encrypted_key, auth_encrypted_key_len, auth_iv);

	// receive ciphertext
	unsigned char *auth_plaintext = new unsigned char[auth_header_msg.total_ciphertext_size];
	unsigned int auth_plainlen = 0;
	unsigned char *temp_plaintext;
	unsigned int temp_plainlen;

	unsigned int auth_cipherlen = recv_data(cl_sd, &my_buff);
	temp_plainlen = asymm_authclient_decipher.decrypt(my_buff.buf, auth_cipherlen, &temp_plaintext);
	memcpy(auth_plaintext, temp_plaintext, temp_plainlen);
	auth_plainlen += temp_plainlen;

	// receive last padded ciphertext
	unsigned int auth_cipherlen_padding = recv_data(cl_sd, &my_buff);
	if(auth_cipherlen_padding > 16)
	{
		printf("error: auth_cipherlen_padding size too big!\n");
		return -1;
	}
	temp_plainlen = asymm_authclient_decipher.decrypt(my_buff.buf, auth_cipherlen_padding, &temp_plaintext);
	memcpy(auth_plaintext + auth_plainlen, temp_plaintext, temp_plainlen);
	auth_plainlen += temp_plainlen;

	unsigned char padding_plaintext[16];
	temp_plainlen = asymm_authclient_decipher.decrypt_end(padding_plaintext);
	memcpy(auth_plaintext + auth_plainlen, padding_plaintext, temp_plainlen);
	auth_plainlen += temp_plainlen;

	// decompose plaintext
	unsigned int pl_offset = 0;

	uint64_t received_server_nonce;
	memcpy(&received_server_nonce, auth_plaintext, 8);
	pl_offset += 8;
	printf("received_server_nonce = %ld\n", received_server_nonce);

	unsigned char session_key[16];
	memcpy(session_key, auth_plaintext + pl_offset, 16);
	pl_offset += 16;

	unsigned char *received_username = new unsigned char[auth_header_msg.username_length];
	memcpy(received_username, auth_plaintext + pl_offset, auth_header_msg.username_length);
	pl_offset += auth_header_msg.username_length;

	unsigned char *received_password = new unsigned char[auth_header_msg.password_length];
	memcpy(received_password, auth_plaintext + pl_offset, auth_header_msg.password_length);
	pl_offset += auth_header_msg.username_length;

	printf("got key:\n");
	print_hex(session_key, 16);
	printf("got: username = %s, password = %s\n", received_username, received_password);

	// 5) Send Ok/no
	simple_msg auth_resp_msg;

	if(received_server_nonce != sr_nonce)
	{
		printf("error: nonces unmatch!\n");
		auth_resp_msg.t = AUTHENTICATION_FAILED;
		send_data(cl_sd, (unsigned char*)&auth_resp_msg, sizeof(auth_resp_msg));
		return -1;
	}

	auth_resp_msg.t = AUTHENTICATION_OK;
	send_data(cl_sd, (unsigned char*)&auth_resp_msg, sizeof(auth_resp_msg));

	// 6) Receive Command
	// 7) Send Response


	// ----------------------------------------------------------------

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
	if( !recv_msg(cl_sd,&s_msg,SEND_FILE) )
	{
		printf("Errore ricezione messaggio SEND_FILE \n");
		return -1;
	}
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
		printf("decrypting chunk(%d) of %d ciphertext bytes\n", i, chunk_cipherlen);

		// do decryption
		unsigned char* chunk_plaintext;
		unsigned int chunk_plainlen = ds.decrypt(chunk_cipher.buf, chunk_cipherlen, &chunk_plaintext);
		total_plainlen += chunk_plainlen;

		// write to file
		fwrite(chunk_plaintext, 1, chunk_plainlen, fp);

		// if latest chunk, compute padding
		if(i == s_msg.chunk_number-1)
		{
			unsigned char padding_plaintext[16];
			unsigned padding_plainlen = ds.decrypt_end(padding_plaintext);
			total_plainlen += padding_plainlen;
			printf("adding last padded block of %d bytes\n", padding_plainlen);

			// write latest block (without padding)
			fwrite(padding_plaintext, 1, padding_plainlen, fp);
		}
	}
}