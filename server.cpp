#include "commonlib/net_wrapper.h"
#include "commonlib/messages.h"
#include "commonlib/commonlib.h"

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <thread>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <vector>
#include <mutex>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <stdexcept>

// ---------------------------- Database Helpers ------------------------------------
#include <sqlite3.h>


std::mutex sql_mutex;
sqlite3 *database;

bool sqlite_check_password(sqlite3 *db, char *username, char *hashed_password)
{
	char prepared_sql[] = "SELECT COUNT(*) FROM users WHERE username = ? AND password = ?;";

	sqlite3_stmt *stmt = NULL;
	
	sql_mutex.lock();
	int rc = sqlite3_prepare_v2(db, prepared_sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		printf("sqlite_check_password: prepare error!\n");
		return false;
	}

	if( sqlite3_bind_text(stmt, 1, username, strlen(username), SQLITE_STATIC) ||
		sqlite3_bind_text(stmt, 2, hashed_password, strlen(hashed_password), SQLITE_STATIC))
	{
		printf("sqlite_check_password: prepare error!\n");
		return false;
	}

	rc = sqlite3_step(stmt);
	// int colCount = sqlite3_column_count(stmt);
	// int type = sqlite3_column_type(stmt, 0);
	int valInt = sqlite3_column_int(stmt, 0);

	rc = sqlite3_finalize(stmt);
	sql_mutex.unlock();

	return valInt;
}

bool open_database(sqlite3 **db, const char *database_path) {
	int rc = sqlite3_open(database_path, db);
	if(rc) {
		printf("Can't open database: %s\n", sqlite3_errmsg(*db));
		sqlite3_close(*db);
		return false;
	}

	return true;
}
// ----------------------------------------------------------------------------------

int sd = -1; //main socket
bool signal_close = false;
unsigned n_sessions = 0;

struct Session {
	uint32_t session_no;
	unsigned char session_key[16];
	uint64_t cl_seq_num;
	uint64_t sr_seq_num;
	uint64_t sr_nonce;
	uint64_t cl_nonce;
	my_buffer my_buff;
	Session(){
		my_buff.buf = NULL;
		my_buff.size = 0;
	}
	~Session(){
		// destroy session_key
		memset(session_key,0,16);
		delete[] my_buff.buf;
	}
};

std::vector<Session*> v_sess;

bool send_hello_msg(int sock, unsigned session_no) {
	hello_msg h;
	h.t = SERVER_HELLO;
	h.nonce = v_sess[session_no]->sr_nonce = v_sess[session_no]->sr_seq_num = generate_nonce();
	convert_to_network_order(&h);
	printf("server sends nonce: %ld\n",v_sess[session_no]->sr_nonce);
	if( send_data(sock,(unsigned char*)&h, sizeof(h)) == sizeof(h) )
		return true;
	else
		return false;

}

bool recv_hello_msg(int sd, unsigned session_no){
	hello_msg h_msg;
	if(	!recv_msg(sd, &h_msg ,CLIENT_HELLO) )
	{
		printf("Error receive CLIENT_HELLO\n");
		return false;
	} else  {
		v_sess[session_no]->cl_nonce = v_sess[session_no]->cl_seq_num = h_msg.nonce;
		return true;
	}
}

bool send_server_verification(int cl_sd, unsigned session_no)
{
	SignatureMaker sm("keys/rsa_server_privkey.pem");

	unsigned char to_sign[16];
	memcpy(to_sign, &v_sess[session_no]->cl_nonce, 8);
	memcpy(to_sign + 8, &v_sess[session_no]->sr_nonce, 8);
	sm.sign(to_sign, 16);

	unsigned char *signature;
	unsigned int signature_len = sm.sign_end(&signature);

	// send client_nonce|server_noncce
	send_data(cl_sd, signature, signature_len);
	printf("sent: signature_len  = %u\n", signature_len);

	return true;
}

bool check_client_identity(int cl_sd, unsigned session_no)
{
	// 4) Validate Client and Get Session key
	// getting session encrypted key
	unsigned int auth_encrypted_key_len = recv_data(cl_sd, &v_sess[session_no]->my_buff);
	if(auth_encrypted_key_len > 10000)
	{
		printf("error: auth_encrypted_key_len = %u invalid size!\n", auth_encrypted_key_len);
		return false;
	}
	unsigned char *auth_encrypted_key = new unsigned char[auth_encrypted_key_len];
	memcpy(auth_encrypted_key, v_sess[session_no]->my_buff.buf, auth_encrypted_key_len);

	// getting session iv
	unsigned char *auth_iv = new unsigned char[EVP_CIPHER_iv_length(EVP_aes_128_cbc())];
	unsigned int auth_iv_len = recv_data(cl_sd, &v_sess[session_no]->my_buff);
	if((int)auth_iv_len != EVP_CIPHER_iv_length(EVP_aes_128_cbc())) {
		printf("error: auth_iv_len = %u instead of %d!\n", auth_iv_len, EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
		return false;
	}
	memcpy(auth_iv, v_sess[session_no]->my_buff.buf, auth_iv_len);


	// getting client authentication header
	client_auth auth_header_msg;
	recv_data(cl_sd, &v_sess[session_no]->my_buff);
	memcpy(&auth_header_msg, v_sess[session_no]->my_buff.buf, sizeof(auth_header_msg));
	convert_to_host_order(&auth_header_msg);

	printf("client header: ciphertext_len = %u, username_length = %u, password_length = %u\n",
		auth_header_msg.total_ciphertext_size, auth_header_msg.username_length, auth_header_msg.password_length);

	DecryptSession asymm_authclient_decipher("keys/rsa_server_privkey.pem", auth_encrypted_key, auth_encrypted_key_len, auth_iv);

	// receive ciphertext
	unsigned int auth_cipherlen = recv_data(cl_sd, &v_sess[session_no]->my_buff);

	// decode ciphertext
	unsigned char *auth_plaintext = new unsigned char[auth_header_msg.total_ciphertext_size];
	unsigned int auth_plainlen = 0;
	asymm_authclient_decipher.decrypt(v_sess[session_no]->my_buff.buf, auth_cipherlen);
	asymm_authclient_decipher.decrypt_end();
	auth_plainlen = asymm_authclient_decipher.flush_plaintext(&auth_plaintext);

	// decompose plaintext
	unsigned int pl_offset = 0;

	uint64_t received_server_nonce;
	memcpy(&received_server_nonce, auth_plaintext, 8);
	pl_offset += 8;
	printf("received_server_nonce = %ld\n", received_server_nonce);

	memcpy(v_sess[session_no]->session_key, auth_plaintext + pl_offset, 16);
	pl_offset += 16;

	unsigned char *received_username = new unsigned char[auth_header_msg.username_length];
	memcpy(received_username, auth_plaintext + pl_offset, auth_header_msg.username_length);
	pl_offset += auth_header_msg.username_length;

	unsigned char *received_password = new unsigned char[auth_header_msg.password_length];
	memcpy(received_password, auth_plaintext + pl_offset, auth_header_msg.password_length);
	pl_offset += auth_header_msg.username_length;

	printf("got key:\n");
	print_hex(v_sess[session_no]->session_key, 16);
	printf("got: username = %s, password = %s\n", received_username, received_password);

	// 5) send auth result
	simple_msg auth_resp_msg;

	if(received_server_nonce != v_sess[session_no]->sr_nonce)
	{
		printf("error: nonces unmatch!\n");
		auth_resp_msg.t = AUTHENTICATION_FAILED;
		send_data(cl_sd, (unsigned char*)&auth_resp_msg, sizeof(auth_resp_msg));
		return false;
	}

	// compute SHA256 password hash
	unsigned char hash_result[32];
	if(!compute_SHA256(received_password, auth_header_msg.password_length - 1, hash_result))
		return false;

	char hash_hex_result[64 + 1];
	SHA1hash_to_string(hash_result, hash_hex_result);
	//printf("Hash: %s\n", hash_hex_result);

	if(!sqlite_check_password(database, (char*)received_username, hash_hex_result))
	{
		printf("error: login failed!\n");
		auth_resp_msg.t = AUTHENTICATION_FAILED;
		send_data(cl_sd, (unsigned char*)&auth_resp_msg, sizeof(auth_resp_msg));
		return false;
	}

	printf("Client authentication success!\n");

	auth_resp_msg.t = AUTHENTICATION_OK;
	send_data(cl_sd, (unsigned char*)&auth_resp_msg, sizeof(auth_resp_msg));

	return true;
}

bool receive_command(int cl_sd, unsigned char **received_command, unsigned int* received_command_len, unsigned session_no)
{
	// getting iv
	unsigned char *command_iv = new unsigned char[EVP_CIPHER_iv_length(EVP_aes_128_cbc())];
	unsigned int command_iv_len = recv_data(cl_sd, &v_sess[session_no]->my_buff);
	memcpy(command_iv, v_sess[session_no]->my_buff.buf, command_iv_len);

	// getting {seqnum|command_str}_Ksess
	unsigned int command_ciphertext_len = recv_data(cl_sd, &v_sess[session_no]->my_buff);
	unsigned char *command_ciphertext = new unsigned char[command_ciphertext_len];
	memcpy(command_ciphertext, v_sess[session_no]->my_buff.buf, command_ciphertext_len);

	// getting HMAC_Ksess{seqnum|command_str}_Ksess
	unsigned int command_hmac_len = recv_data(cl_sd, &v_sess[session_no]->my_buff);
	unsigned char *command_hmac = new unsigned char[command_hmac_len];
	memcpy(command_hmac, v_sess[session_no]->my_buff.buf, command_hmac_len);

	// making HMAC_Ksess{seqnum|command_str}_Ksess
	unsigned char *computed_hmac;
	HMACMaker hm(v_sess[session_no]->session_key, 16);
	hm.hash(command_ciphertext, command_ciphertext_len);
	hm.hash_end(&computed_hmac);

	if(CRYPTO_memcmp(computed_hmac, command_hmac, HMAC_LENGTH) != 0)
	{
		printf("HMAC authentication failed!\n");
		return false;
	}

	printf("HMAC authentication success!\n");

	// decrypt {seqnum|command_str}_Ksess
	SymmetricCipher sc(EVP_aes_128_cbc(), v_sess[session_no]->session_key, command_iv);
	unsigned char *command_plaintext;
	unsigned int command_plainlen;
	sc.decrypt(command_ciphertext, command_ciphertext_len);
	sc.decrypt_end();
	command_plainlen = sc.flush_plaintext(&command_plaintext);

	// verify sequence number
	uint64_t received_seqno;
	memcpy((void*)&received_seqno, command_plaintext, sizeof(uint64_t));

	char *command_text = (char*)&command_plaintext[sizeof(uint64_t)];
	unsigned int command_text_len = command_plainlen - sizeof(uint64_t); // Must be checked

	if(received_seqno != v_sess[session_no]->sr_seq_num)
	{
		printf("Invalid sequence number! (%lu != %lu)\n", received_seqno, v_sess[session_no]->sr_seq_num);
		return false;
	}

	// increment server sequence number
	v_sess[session_no]->sr_seq_num++;

	// return receive command
	*received_command = new unsigned char[command_text_len];
	memcpy(*received_command, command_text, command_text_len);
	*received_command_len = command_text_len;

	//printf("Received command: %s\n", command_text);
	printf("Received command. command_text_len:%d\n", command_text_len);
	return true;
}

bool send_str_response(int sd, char data_response[], unsigned int data_response_len, unsigned session_no)
{
	unsigned char *data_resp_iv = new unsigned char[EVP_CIPHER_iv_length(EVP_aes_128_cbc())];
	generate_iv(data_resp_iv);
	send_data(sd, data_resp_iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc()));

	SymmetricCipher sc(EVP_aes_128_cbc(), v_sess[session_no]->session_key, data_resp_iv);

	// encrypt cl_seq_num|data_response
	sc.encrypt((unsigned char*)&v_sess[session_no]->cl_seq_num, sizeof(v_sess[session_no]->cl_seq_num));
	sc.encrypt((unsigned char*)data_response, data_response_len);
	sc.encrypt_end();
	unsigned char *command_ciphertext;
	unsigned int command_cipherlen = sc.flush_ciphertext(&command_ciphertext);

	// send {seqnum|data_response}_Ksess
	send_data(sd, command_ciphertext, command_cipherlen);

	// make hmac from {seqnum|data_response}_Ksess
	unsigned char *hash_result;
	unsigned int hash_len;

	HMACMaker hc(v_sess[session_no]->session_key, 16);
	hc.hash(command_ciphertext, command_cipherlen);
	hash_len = hc.hash_end(&hash_result);

	// send HMAC_Ksess{ eqnum|data_response}_Ksess }
	send_data(sd, hash_result, hash_len);

	// increment server sequence number
	v_sess[session_no]->cl_seq_num++;

	return true;
}

unsigned int divide_upper(unsigned int dividend, unsigned int divisor)
{
    return 1 + ((dividend - 1) / divisor);
}

bool send_file_response(int cl_sd, const char filename[], unsigned session_no)
{
	// getting file size
	FILE *fp;
	unsigned int filesize = open_file_r(filename, &fp);
	// sizeof(uint64_t) is added for client_nonce
	unsigned int chunk_count = divide_upper(filesize + sizeof(uint64_t), CHUNK_SIZE);
	printf("File size = %u, Chunk size = %d, Chunk count = %d\n", filesize, CHUNK_SIZE, chunk_count);

	// generate and send iv
	unsigned char *data_resp_iv = new unsigned char[EVP_CIPHER_iv_length(EVP_aes_128_cbc())];
	generate_iv(data_resp_iv);
	send_data(cl_sd, data_resp_iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc()));

	// send chunk transfer details
	send_file_msg s_msg = {SEND_FILE, CHUNK_SIZE, chunk_count + 1};  // +1 for padding
	convert_to_network_order(&s_msg);
	send_data(cl_sd, (unsigned char*)&s_msg, sizeof(s_msg));

	// we need to compute {seqnum|data_response}_Ksess and hash it
	SymmetricCipher sc(EVP_aes_128_cbc(), v_sess[session_no]->session_key, data_resp_iv);
	HMACMaker hc(v_sess[session_no]->session_key, 16);

	// encrypt cl_seq_num|data_response
	sc.encrypt((unsigned char*)&v_sess[session_no]->cl_seq_num, sizeof(v_sess[session_no]->cl_seq_num));

	unsigned char datachunk[CHUNK_SIZE];
	for(unsigned int i=0; i<chunk_count; i++)
	{
		// read next chunk from file
		unsigned int chunk_plainlen = fread(datachunk, 1, CHUNK_SIZE, fp);
		printf("encrypting chunk of %d plaintext bytes\n", chunk_plainlen);

		// do encryption
		unsigned char *chunk_ciphertext;
		sc.encrypt(datachunk, chunk_plainlen);
		unsigned int chunk_cipherlen = sc.flush_ciphertext(&chunk_ciphertext);

		// hash partial ciphertext
		hc.hash(chunk_ciphertext, chunk_cipherlen);

		// send encrypted data
		printf("sending chunk(%d) of %d bytes\n", i, chunk_cipherlen);
		send_data(cl_sd, chunk_ciphertext, chunk_cipherlen);
		delete[] chunk_ciphertext;

		// if last chunk
		if(i==chunk_count-1)
		{
			// compute padding
			unsigned char *padding_ciphertext;
			sc.encrypt_end();
			unsigned int padding_cipherlen = sc.flush_ciphertext(&padding_ciphertext);

			// send padding
			printf("sending padding of %d bytes\n", padding_cipherlen);

			// hash partial ciphertext
			hc.hash(padding_ciphertext, padding_cipherlen);

			send_data(cl_sd, padding_ciphertext, padding_cipherlen);
			delete[] padding_ciphertext;
		}
	}

	// compute hash
	unsigned char *hash_result;
	unsigned int hash_len;
	hash_len = hc.hash_end(&hash_result);

	// send HMAC_Ksess{ {eqnum|data_response}_Ksess }
	send_data(cl_sd, hash_result, hash_len);

	// increment server sequence number
	v_sess[session_no]->cl_seq_num++;

	return true;
}

void list_command_response(int cl_sd, unsigned session_no)
{
	char *data_response;
	printf("client %d LIST_FILE\n",session_no);
	std::string s = show_dir_content("./files/"); // aggiustare
	data_response = new char[s.length()+1];
	memcpy(data_response,s.c_str(),s.length()+1);

	if( !send_str_response(cl_sd, data_response, strlen(data_response)+1, session_no) )
		throw std::runtime_error("cannot send response");
}

void download_command_response(int cl_sd, unsigned session_no, download_file* dwn_header)
{
	if(!send_file_response(cl_sd, "files/file.txt", session_no))
		throw std::runtime_error("cannot send file data");
}


int handler_fun(int cl_sd, unsigned session_no){
	v_sess.push_back(new Session());

	// 1) Get Client Nonce
	if( !recv_hello_msg(cl_sd, session_no) )
		return -1;

	// 2) Send Server Nonce
	if ( !send_hello_msg(cl_sd, session_no) )
		return -1;

	// 3) Send Server verification infos
	// sign {client_nonce|server_nonce}_Kpub
	if ( !send_server_verification(cl_sd, session_no) )
		return -1;

	// 4/5) Check Client identity / Send auth response
	// receive {client_nonce|session key|username|password}_Kpub
	// send authok or authfailed
	if ( !check_client_identity(cl_sd, session_no) )
		return -1;

	while(true)
	{
		// 6) Receive Command
		// receive {seqnum|command_str}_Ksess | HMAC{{seqnum|command_str}_Ksess}_Ksess
		unsigned char *received_command = NULL;
		unsigned int received_command_len;
		if(!receive_command(cl_sd, &received_command, &received_command_len, session_no)){
			printf("error received_command\n");
			return -1;
		}
		// 7) Send Response
		// send {seqnum|data_response}_Ksess | HMAC{{seqnum|data_response}_Ksess}_Ksess
		if( convert_to_host_order(received_command) == -1 ){
			printf("Invalid msg received from client. session_no:%u\n",session_no);
		}

		if(((simple_msg*)received_command)->t == LIST_FILE)
			list_command_response(cl_sd, session_no);
		else if(((simple_msg*)received_command)->t == DOWNLOAD_FILE)
			download_command_response(cl_sd, session_no, (download_file*)received_command);
	}

	close(cl_sd);

	delete v_sess[session_no];

	return 0;
}

void close_all(void){
	close(sd);
}

int main(int argc, char** argv)
{
	ERR_load_crypto_strings();

	uint16_t server_port;
	ConnectionTCP conn;

	if( argc < 2 ){
		printf("use: ./server port");
		return -1;
	}
	sscanf(argv[1],"%hd",&server_port);	
	
	atexit(close_all);

	if( !open_database(&database, "database.sqlite3") ) {
		printf("error: failed to open database\n");
		return -1;
	}

	sd = open_tcp_server(server_port);
	if( sd == -1 ){
		return -1;
	}

	while( 1 ) {
		int cl_sd = accept_tcp_server(sd,&conn);
		std::thread threadObj(handler_fun,cl_sd,n_sessions++);
		threadObj.detach();
	}

	return 0;
}