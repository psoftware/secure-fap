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

#include <stdexcept>

// --------- Console Functions ----------
#include <stdlib.h>
#include <termios.h>

struct termios oflags, nflags;

void disable_console_echo()
{
	tcgetattr(fileno(stdin), &oflags);
	nflags = oflags;
	nflags.c_lflag &= ~ECHO;
	nflags.c_lflag |= ECHONL;

	if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
		throw std::runtime_error("can't disable echo");
	}
}

void enable_console_echo()
{
	if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0) {
		perror("tcsetattr");
		throw std::runtime_error("can't enable echo");
	}
}

// --------------------------------------

my_buffer my_buff;

uint64_t cl_nonce;
uint64_t sr_nonce;

uint64_t cl_seq_num;
uint64_t sr_seq_num;

unsigned char session_key[16];

int send_hello_msg(int sock) {
	hello_msg h;
	h.t = CLIENT_HELLO;
	h.nonce = cl_nonce = cl_seq_num = generate_nonce();
	convert_to_network_order(&h);
	printf("client sends nonce: %ld\n",cl_nonce);
	return send_data(sock,(unsigned char*)&h, sizeof(h));
}

int analyze_message(unsigned char* buf)
{
	convert_to_host_order(buf);
	switch( ((simple_msg*)buf)->t ) {
  		case SERVER_HELLO:
  			sr_nonce = sr_seq_num = ((hello_msg*)buf)->nonce;
  			printf("Server nonce received: %ld\n",sr_nonce);
  			break;
		default:
			return -2;
	}

	return 0;
}

bool verify_server_identity(int sd)
{
	unsigned int signature_len = recv_data(sd, &my_buff);
	unsigned char *signature = new unsigned char[signature_len];
	memcpy(signature, my_buff.buf, signature_len);

	SignatureVerifier sv("keys/rsa_server_pubkey.pem");

	unsigned char expected_signed[16];
	memcpy(expected_signed, &cl_nonce, 8);
	memcpy(expected_signed + 8, &sr_nonce, 8);
	sv.verify(expected_signed, 16);

	// compare nonces
	if(!sv.verify_end(signature, signature_len))
	{
		printf("Signature not verified!\n");
		return false;
	}

	printf("Server Authentication Success!\n");
	return true;
}

bool send_client_identification(int sd, char auth_username[], char auth_secret[])
{
	// generate session key
	generate_session_key(session_key);

	// setup PublicKey cipher
	EncryptSession asymm_authclient_cipher("keys/rsa_server_pubkey.pem");

	// ## plaintext data
	// send iv and encrypted key generated by EncryptSession
	unsigned char *auth_iv = asymm_authclient_cipher.get_iv();
	unsigned char *auth_pk_encrypted_key;
	unsigned int auth_pk_encrypted_key_len = asymm_authclient_cipher.get_session_key(&auth_pk_encrypted_key);
	send_data(sd, auth_pk_encrypted_key, auth_pk_encrypted_key_len);
	send_data(sd, auth_iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc()));

	// ## ciphered data
	unsigned char *auth_ciphertext;
	unsigned int auth_cipherlen;
	// client nonce encrypt
	asymm_authclient_cipher.encrypt((unsigned char*)&sr_nonce, 8);
	// session key encrypt
	asymm_authclient_cipher.encrypt(session_key, 16);
	// username encrypt
	asymm_authclient_cipher.encrypt((unsigned char*)auth_username, strlen(auth_username) + 1);
	// password encrypt
	asymm_authclient_cipher.encrypt((unsigned char*)auth_secret, strlen(auth_secret) + 1);
	asymm_authclient_cipher.encrypt_end();
	auth_cipherlen = asymm_authclient_cipher.flush_ciphertext(&auth_ciphertext);

	// send client auth header (server needs sizes)
	client_auth auth_header_msg = {CLIENT_AUTHENTICATION, auth_cipherlen, (unsigned int)strlen(auth_username) + 1, (unsigned int)strlen(auth_secret) + 1};
	printf("client header: ciphertext_len = %u, username_length = %u, password_length = %u\n",
		auth_header_msg.total_ciphertext_size, auth_header_msg.username_length, auth_header_msg.password_length);

	convert_to_network_order(&auth_header_msg);
	send_data(sd, (unsigned char*)&auth_header_msg, sizeof(auth_header_msg));

	// send ciphertext and padded ciphertext
	send_data(sd, auth_ciphertext, auth_cipherlen);

	return true;
}

bool wait_for_authentication_response(int sd)
{
	simple_msg auth_response_msg;
	recv_data(sd, &my_buff);
	memcpy(&auth_response_msg, my_buff.buf, sizeof(auth_response_msg));

	if(auth_response_msg.t == AUTHENTICATION_FAILED)
	{
		printf("Authentication Failed!\n");
		return false;
	}

	return true;
}

/*
bool send_command(int sd, char command_str[], unsigned int command_len)
{
	unsigned char *command_iv = new unsigned char[EVP_CIPHER_iv_length(EVP_aes_128_cbc())];
	generate_iv(command_iv);
	send_data(sd, command_iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc()));

	SymmetricCipher sc(EVP_aes_128_cbc(), session_key, command_iv);

	// encrypt sr_seq_num|command_str
	sc.encrypt((unsigned char*)&sr_seq_num, sizeof(sr_seq_num));
	sc.encrypt((unsigned char*)command_str, command_len);
	sc.encrypt_end();
	unsigned char *command_ciphertext;
	unsigned int command_cipherlen = sc.flush_ciphertext(&command_ciphertext);

	// send {seqnum|command_str}_Ksess
	send_data(sd, command_ciphertext, command_cipherlen);

	// make hmac from {seqnum|command_str}_Ksess
	unsigned char *hash_result;
	unsigned int hash_len;

	HMACMaker hc(session_key, 16);
	hc.hash(command_ciphertext, command_cipherlen);
	hash_len = hc.hash_end(&hash_result);

	// send HMAC_Ksess{ eqnum|command_str}_Ksess }
	send_data(sd, hash_result, hash_len);

	// increment server sequence number
	sr_seq_num++;

	return true;
}*/

bool send_command(int sd, void *msg_str, size_t msg_len)
{
	unsigned char *command_iv = new unsigned char[EVP_CIPHER_iv_length(EVP_aes_128_cbc())];
	generate_iv(command_iv);
	send_data(sd, command_iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc()));

	SymmetricCipher sc(EVP_aes_128_cbc(), session_key, command_iv);

	convert_to_network_order(msg_str);

	// encrypt sr_seq_num|command_str
	sc.encrypt((unsigned char*)&sr_seq_num, sizeof(sr_seq_num));
	sc.encrypt((unsigned char*)msg_str, msg_len);
	sc.encrypt_end();
	unsigned char *command_ciphertext;
	unsigned int command_cipherlen = sc.flush_ciphertext(&command_ciphertext);

	printf("command_cipherlen:%d\n",command_cipherlen);
	// send {seqnum|command_str}_Ksess
	send_data(sd, command_ciphertext, command_cipherlen);

	// make hmac from {seqnum|command_str}_Ksess
	unsigned char *hash_result;
	unsigned int hash_len;

	HMACMaker hc(session_key, 16);
	hc.hash(command_ciphertext, command_cipherlen);
	hash_len = hc.hash_end(&hash_result);

	// send HMAC_Ksess{ eqnum|command_str}_Ksess }
	send_data(sd, hash_result, hash_len);

	// increment server sequence number
	sr_seq_num++;

	return true;
}

bool receive_str_response(int sd, unsigned char **received_data, unsigned int* received_data_len)
{
	// getting iv
	unsigned char *command_iv = new unsigned char[EVP_CIPHER_iv_length(EVP_aes_128_cbc())];
	unsigned int command_iv_len = recv_data(sd, &my_buff);
	memcpy(command_iv, my_buff.buf, command_iv_len);

	// getting {seqnum|command_str}_Ksess
	unsigned int command_ciphertext_len = recv_data(sd, &my_buff);
	unsigned char *command_ciphertext = new unsigned char[command_ciphertext_len];
	memcpy(command_ciphertext, my_buff.buf, command_ciphertext_len);

	// getting HMAC_Ksess{seqnum|command_str}_Ksess
	unsigned int command_hmac_len = recv_data(sd, &my_buff);
	unsigned char *command_hmac = new unsigned char[command_hmac_len];
	memcpy(command_hmac, my_buff.buf, command_hmac_len);

	// making HMAC_Ksess{seqnum|command_str}_Ksess
	unsigned char *computed_hmac;
	HMACMaker hm(session_key, 16);
	hm.hash(command_ciphertext, command_ciphertext_len);
	hm.hash_end(&computed_hmac);

	if(CRYPTO_memcmp(computed_hmac, command_hmac, HMAC_LENGTH) != 0)
	{
		printf("receive_str_response: HMAC authentication failed!\n");
		return false;
	}

	printf("receive_str_response: HMAC authentication success!\n");

	// decrypt {seqnum|command_str}_Ksess
	SymmetricCipher sc(EVP_aes_128_cbc(), session_key, command_iv);
	unsigned char *command_plaintext;
	unsigned int command_plainlen;
	sc.decrypt(command_ciphertext, command_ciphertext_len);
	sc.decrypt_end();
	command_plainlen = sc.flush_plaintext(&command_plaintext);

	// verify sequence number
	uint64_t received_seqno;
	memcpy((void*)&received_seqno, command_plaintext, sizeof(uint64_t));

	char *data_text = (char*)&command_plaintext[sizeof(uint64_t)];
	unsigned int data_text_len = command_plainlen - sizeof(uint64_t); // Must be checked

	if(received_seqno != cl_seq_num)
	{
		printf("receive_str_response: Invalid sequence number! (%lu != %lu)\n", received_seqno, cl_seq_num);
		return false;
	}

	// increment server sequence number
	cl_seq_num++;

	// return receive command
	*received_data = new unsigned char[data_text_len];
	memcpy(*received_data, data_text, data_text_len);
	*received_data_len = data_text_len;
	printf("receive_str_response: size = %u\n", data_text_len);

	return true;
}

bool receive_file_response(int sd)
{
	FILE *fp;
	open_file_w("ricevuto.txt", &fp);

	// getting iv
	unsigned char *iv = new unsigned char[EVP_CIPHER_iv_length(EVP_aes_128_cbc())];
	unsigned int iv_len = recv_data(sd, &my_buff);
	memcpy(iv, my_buff.buf, iv_len);

	// get file transfer header
	send_file_msg s_msg;
	if(!recv_msg(sd, &s_msg, SEND_FILE)) {
		printf("Errore ricezione messaggio SEND_FILE \n");
		return -1;
	}

	SymmetricCipher sc(EVP_aes_128_cbc(), session_key, iv);
	HMACMaker hm(session_key, 16);

	unsigned int total_plainlen = 0;
	// initialize receive buffer
	my_buffer chunk_cipher;
	chunk_cipher.buf = NULL;
	chunk_cipher.size = 0;
	for(unsigned int i=0; i < s_msg.chunk_number; i++)
	{
		// get chunk from tcp socket
		unsigned int chunk_cipherlen = recv_data(sd, &chunk_cipher);
		printf("decrypting chunk(%d) of %d ciphertext bytes\n", i, chunk_cipherlen);

		// hash partial encrypted text
		hm.hash(chunk_cipher.buf, chunk_cipherlen);

		// do decryption
		unsigned char* chunk_plaintext;
		sc.decrypt(chunk_cipher.buf, chunk_cipherlen);
		unsigned int chunk_plainlen = sc.flush_plaintext(&chunk_plaintext);

		// if first chunk, nonce must be extracted and verified
		if(i == 0)
		{
			if(chunk_cipherlen < sizeof(uint64_t))
				return false;

			uint64_t received_seqno;
			memcpy((void*)&received_seqno, chunk_plaintext, sizeof(uint64_t));

			// verify sequence number
			if(received_seqno != cl_seq_num) {
				printf("receive_str_response: Invalid sequence number! (%lu != %lu)\n", received_seqno, cl_seq_num);
				return false;
			}

			// chunk_plaintext must be purified from received
			chunk_plaintext += sizeof(uint64_t);
			chunk_plainlen -= sizeof(uint64_t);
		}

		total_plainlen += chunk_plainlen;

		// write to file
		fwrite(chunk_plaintext, 1, chunk_plainlen, fp);

		// if latest chunk, compute padding
		if(i == s_msg.chunk_number-1)
		{
			unsigned char *padding_plaintext;
			sc.decrypt_end();
			unsigned padding_plainlen = sc.flush_plaintext(&padding_plaintext);
			total_plainlen += padding_plainlen;
			printf("adding last padded block of %d bytes\n", padding_plainlen);

			// write latest block (without padding)
			fwrite(padding_plaintext, 1, padding_plainlen, fp);
		}
	}

	// getting from client HMAC_Ksess{seqnum|command_str}_Ksess
	unsigned int received_hmac_len = recv_data(sd, &my_buff);
	unsigned char *received_hmac = new unsigned char[received_hmac_len];
	memcpy(received_hmac, my_buff.buf, received_hmac_len);

	// finally compute HMAC_Ksess{seqnum|command_str}_Ksess
	unsigned char *computed_hmac;
	hm.hash_end(&computed_hmac);

	// verify hash
	if(CRYPTO_memcmp(computed_hmac, received_hmac, HMAC_LENGTH) != 0)
	{
		printf("receive_str_response: HMAC authentication failed!\n");
		return false;
	}

	printf("receive_str_response: HMAC authentication success!\n");

	// increment server sequence number
	cl_seq_num++;

	return true;
}

int main(int argc, char **argv)
{
	ERR_load_crypto_strings();

	int sd;
	uint16_t server_port;

	my_buff.buf = NULL;
	my_buff.size = 0;

	// Parsing parameters
	if( argc < 3 ){
		perror("use: ./client server_ip port");
		return -1;
	}
	sscanf(argv[2],"%hd",&server_port);

	sd = start_tcp_connection(argv[1], server_port);
	if( sd < 0 )
		return -1;

	// 1) Send Client Nuance
	send_hello_msg(sd);

	// 2) Get Server Nuance
	recv_data(sd,&my_buff);
	analyze_message(my_buff.buf);

	// 3) Verify Server Identity
	// receive E(Kpriv, client_nonce|server_nonce)
	if(!verify_server_identity(sd))
		return -1;

	// 4) Send client verification infos and KeySession
	// send {client_nonce|session key|username|password}_Kpub

	// ask for credentials
	char *auth_username = NULL;
	char *auth_secret = NULL;
	printf("Username: ");
	fflush(stdout);
	scanf("%ms", &auth_username);
	if(!auth_username)
		return -1;

	printf("Password: ");
	fflush(stdout);
	disable_console_echo();
	scanf("%ms", &auth_secret);
	enable_console_echo();
	if(!auth_secret)
		return -1;

	if(!send_client_identification(sd, auth_username, auth_secret))
		return -1;

	// 5) Waiting for AuthOK or AuthFailed
	if(!wait_for_authentication_response(sd))
		return -1;

	printf("Authentication success!\n");

	// 6) Send Command
	// send {seqnum|command_str}_Ksess | HMAC{{seqnum|command_str}_Ksess}_Ksess
	//char command_str[] = "DOWNLOAD 4kporn.mkv";
	//download_file cmd = {DOWNLOAD_FILE,1};
	simple_msg cmd = {LIST_FILE};
	if(!send_command(sd, &cmd, sizeof(cmd)))
		return -1;

	// 7) Receive Response
	unsigned char *received_data;
	unsigned int received_data_len;
	if(!receive_str_response(sd, &received_data, &received_data_len))
		return -1;

	printf("Received response:\n%s\n", received_data);

	// TEST
	receive_file_response(sd);

	close(sd);

	return 0;
}
