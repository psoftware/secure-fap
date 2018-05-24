#include "commonlib/net_wrapper.h"
#include "commonlib/net_exception.h"
#include "commonlib/messages.h"
#include "commonlib/commonlib.h"
#include "commonlib/log.h"

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
		LOG_ERROR("sqlite_check_password: prepare error!\n");
		return false;
	}

	if( sqlite3_bind_text(stmt, 1, username, strlen(username), SQLITE_STATIC) ||
		sqlite3_bind_text(stmt, 2, hashed_password, strlen(hashed_password), SQLITE_STATIC))
	{
		LOG_ERROR("sqlite_check_password: prepare error!\n");
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
		LOG_ERROR("Can't open database: %s\n", sqlite3_errmsg(*db));
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
	unsigned char hmac_key[16];
	char username[255];
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
		secure_zero(session_key,16);
		secure_zero(hmac_key,16);
		delete[] my_buff.buf;
	}
};

std::vector<Session*> v_sess;

void send_hello_msg(int sock, unsigned session_no) {
	hello_msg h;
	h.t = SERVER_HELLO;
	h.nonce = v_sess[session_no]->sr_nonce = v_sess[session_no]->sr_seq_num = generate_nonce();
	convert_to_network_order(&h);
	LOG_DEBUG("server sends nonce: %ld\n",v_sess[session_no]->sr_nonce);

	if( !(send_data(sock,(unsigned char*)&h, sizeof(h)) == sizeof(h)) )
		throw net_exception("send_hello_msg: cannot send SERVER_HELLO");
}

void recv_hello_msg(int sd, unsigned session_no){
	hello_msg h_msg;
	if(	!recv_msg(sd, &h_msg ,CLIENT_HELLO) )
		throw net_exception("recv_hello_msg: cannot receive CLIENT_HELLO");
	else
		v_sess[session_no]->cl_nonce = v_sess[session_no]->cl_seq_num = h_msg.nonce;
}

void send_server_verification(int cl_sd, unsigned session_no)
{
	SignatureMaker sm("keys/rsa_server_digsign_privkey.pem");

	unsigned char to_sign[16];
	memcpy(to_sign, &v_sess[session_no]->cl_nonce, 8);
	memcpy(to_sign + 8, &v_sess[session_no]->sr_nonce, 8);
	sm.sign(to_sign, 16);

	unsigned char *signature;
	unsigned int signature_len = sm.sign_end(&signature);

	// send client_nonce|server_noncce
	if(send_data(cl_sd, signature, signature_len) != (int)signature_len)
		throw net_exception("send_server_verification: cannot send signature");
	LOG_DEBUG("sent: signature_len  = %u\n", signature_len);
}

bool check_client_identity(int cl_sd, unsigned session_no)
{
	bool result = false;

	// 4) Validate Client and Get Session key
	// getting session encrypted key
	unsigned int auth_encrypted_key_len = recv_data(cl_sd, &v_sess[session_no]->my_buff);
	if(auth_encrypted_key_len > 10000)
	{
		LOG_ERROR("error: auth_encrypted_key_len = %u invalid size!\n", auth_encrypted_key_len);
		throw net_exception("check_client_identity: cannot receive signature");
	}
	unsigned char *auth_encrypted_key = new unsigned char[auth_encrypted_key_len];
	memcpy(auth_encrypted_key, v_sess[session_no]->my_buff.buf, auth_encrypted_key_len);

	// getting session iv
	unsigned char *auth_iv = new unsigned char[EVP_CIPHER_iv_length(EVP_aes_128_cbc())];
	unsigned int auth_iv_len = recv_data(cl_sd, &v_sess[session_no]->my_buff);
	if((int)auth_iv_len != EVP_CIPHER_iv_length(EVP_aes_128_cbc())) {
		LOG_ERROR("error: auth_iv_len = %u instead of %d!\n", auth_iv_len, EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
		throw net_exception("check_client_identity: cannot receive iv");
	}
	memcpy(auth_iv, v_sess[session_no]->my_buff.buf, auth_iv_len);


	// getting client authentication header
	client_auth auth_header_msg;
	if(recv_data(cl_sd, &v_sess[session_no]->my_buff) == -1)
		throw net_exception("check_client_identity: cannot receive auth_header_msg");
	memcpy(&auth_header_msg, v_sess[session_no]->my_buff.buf, sizeof(auth_header_msg));
	convert_to_host_order(&auth_header_msg);

	LOG_DEBUG("client header: ciphertext_len = %u, username_length = %u, password_length = %u\n",
		auth_header_msg.total_ciphertext_size, auth_header_msg.username_length, auth_header_msg.password_length);

	DecryptSession asymm_authclient_decipher("keys/rsa_server_privkey.pem", auth_encrypted_key, auth_encrypted_key_len, auth_iv);

	// receive ciphertext
	int auth_cipherlen = recv_data(cl_sd, &v_sess[session_no]->my_buff);
	if(auth_cipherlen == -1)
		throw net_exception("check_client_identity: cannot receive auth_header_msg");

	// decode ciphertext
	unsigned char *auth_plaintext = NULL;
	unsigned int auth_plainlen = 0;
	asymm_authclient_decipher.decrypt(v_sess[session_no]->my_buff.buf, auth_cipherlen);
	asymm_authclient_decipher.decrypt_end();
	auth_plainlen = asymm_authclient_decipher.flush_plaintext(&auth_plaintext);

	// decompose plaintext
	unsigned int pl_offset = 0;

	uint64_t received_server_nonce;
	memcpy(&received_server_nonce, auth_plaintext, 8);
	pl_offset += 8;
	LOG_DEBUG("received_server_nonce = %ld\n", received_server_nonce);

	memcpy(v_sess[session_no]->session_key, auth_plaintext + pl_offset, 16);
	pl_offset += 16;

	memcpy(v_sess[session_no]->hmac_key, auth_plaintext + pl_offset, 16);
	pl_offset += 16;

	unsigned char *received_username = new unsigned char[auth_header_msg.username_length];
	memcpy(received_username, auth_plaintext + pl_offset, auth_header_msg.username_length);
	pl_offset += auth_header_msg.username_length;

	unsigned char *received_password = new unsigned char[auth_header_msg.password_length];
	memcpy(received_password, auth_plaintext + pl_offset, auth_header_msg.password_length);
	pl_offset += auth_header_msg.username_length;

	LOG_DEBUG("got key:\n");
	//print_hex(v_sess[session_no]->session_key, 16);
	LOG_DEBUG("got: username = %s, password = %s\n", received_username, received_password);
	memcpy(v_sess[session_no]->username,received_username,auth_header_msg.username_length);

	// 5) send auth result
	simple_msg auth_resp_msg;

	if(received_server_nonce != v_sess[session_no]->sr_nonce)
	{
		LOG_ERROR("error: nonces unmatch!\n");
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
		LOG_ERROR("error: login failed!\n");
		auth_resp_msg.t = AUTHENTICATION_FAILED;
		result = false;
	} else {
		LOG_INFO("Client authentication success!\n");
		auth_resp_msg.t = AUTHENTICATION_OK;
		result = true;
	}

	send_data(cl_sd, (unsigned char*)&auth_resp_msg, sizeof(auth_resp_msg));

	unsigned char *hashmac_result = NULL;
	unsigned int hashmac_len;

	HMACMaker hc(v_sess[session_no]->hmac_key, 16);
	hc.hash((unsigned char*)&auth_resp_msg, sizeof(auth_resp_msg));
	hashmac_len = hc.hash_end(&hashmac_result);

	// send HMAC_Khmac{ AUTHENTICATION }
	send_data(cl_sd, hashmac_result, hashmac_len);

	secure_zero(received_password,auth_header_msg.password_length);
	delete[] received_password;
	delete[] received_username;
	delete[] auth_iv;
	delete[] auth_plaintext;
	delete[] hashmac_result;

	return result;
}

bool receive_command(int cl_sd, unsigned char **received_command, unsigned int* received_command_len, unsigned session_no)
{
	// getting iv
	unsigned char *command_iv = new unsigned char[EVP_CIPHER_iv_length(EVP_aes_128_cbc())];
	int command_iv_len = recv_data(cl_sd, &v_sess[session_no]->my_buff);
	if(command_iv_len == -1)
		throw net_exception("receive_command: cannot receive command_iv");
	memcpy(command_iv, v_sess[session_no]->my_buff.buf, command_iv_len);

	// getting {seqnum|command_str}_Ksess
	int command_ciphertext_len = recv_data(cl_sd, &v_sess[session_no]->my_buff);
	if(command_ciphertext_len == -1)
		throw net_exception("receive_command: cannot receive command_ciphertext");
	unsigned char *command_ciphertext = new unsigned char[command_ciphertext_len];
	memcpy(command_ciphertext, v_sess[session_no]->my_buff.buf, command_ciphertext_len);

	// getting HMAC_Khmac{seqnum|command_str}_Ksess
	int command_hmac_len = recv_data(cl_sd, &v_sess[session_no]->my_buff);
	if(command_hmac_len == -1)
		throw net_exception("receive_command: cannot receive command_hmac_len");
	unsigned char *command_hmac = new unsigned char[command_hmac_len];
	memcpy(command_hmac, v_sess[session_no]->my_buff.buf, command_hmac_len);

	// making HMAC_Ksess{seqnum|command_str}_Kmac
	unsigned char *computed_hmac;
	HMACMaker hm(v_sess[session_no]->hmac_key, 16);
	hm.hash(command_ciphertext, command_ciphertext_len);
	hm.hash_end(&computed_hmac);

	if(CRYPTO_memcmp(computed_hmac, command_hmac, HMAC_LENGTH) != 0)
	{
		LOG_INFO("HMAC authentication failed!\n");
		return false;
	}

	LOG_INFO("HMAC authentication success!\n");

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
		LOG_ERROR("Invalid sequence number! (%lu != %lu)\n", received_seqno, v_sess[session_no]->sr_seq_num);
		return false;
	}

	// increment server sequence number
	v_sess[session_no]->sr_seq_num++;

	// return receive command
	*received_command = new unsigned char[command_text_len];
	memcpy(*received_command, command_text, command_text_len);
	*received_command_len = command_text_len;

	//printf("Received command: %s\n", command_text);
	LOG_DEBUG("Received command. command_text_len:%d\n", command_text_len);
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

	HMACMaker hc(v_sess[session_no]->hmac_key, 16);
	hc.hash(command_ciphertext, command_cipherlen);
	hash_len = hc.hash_end(&hash_result);

	// send HMAC_Khmac{ {seqnum|data_response}_Ksess }
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
	uint8_t response_code = 0;

	// getting file size
	FILE *fp;
	unsigned int filesize = open_file_r(filename, &fp);
	if(filesize == 0)
		response_code = 0; // file is non existent
	else
		response_code = 1;

	// sizeof(uint64_t) is added for client_nonce
	unsigned int chunk_count = divide_upper(filesize + sizeof(uint64_t), CHUNK_SIZE);
	LOG_DEBUG("File size = %u, Chunk size = %d, Chunk count = %d\n", filesize, CHUNK_SIZE, chunk_count);

	// generate and send iv
	unsigned char *data_resp_iv = new unsigned char[EVP_CIPHER_iv_length(EVP_aes_128_cbc())];
	generate_iv(data_resp_iv);
	send_data(cl_sd, data_resp_iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc()));

	// send chunk transfer details
	send_file_msg s_msg = {SEND_FILE, response_code, CHUNK_SIZE, chunk_count + 1};  // +1 for padding
	convert_to_network_order(&s_msg);
	send_data(cl_sd, (unsigned char*)&s_msg, sizeof(s_msg));

	// if file does not exists, then don't go on
	if(response_code == 0)
		return false;

	// we need to compute {seqnum|data_response}_Ksess and hash it
	SymmetricCipher sc(EVP_aes_128_cbc(), v_sess[session_no]->session_key, data_resp_iv);
	HMACMaker hc(v_sess[session_no]->hmac_key, 16);

	// encrypt cl_seq_num|data_response
	sc.encrypt((unsigned char*)&v_sess[session_no]->cl_seq_num, sizeof(v_sess[session_no]->cl_seq_num));

	unsigned char datachunk[CHUNK_SIZE];
	for(unsigned int i=0; i<chunk_count; i++)
	{
		// read next chunk from file
		unsigned int chunk_plainlen = fread(datachunk, 1, CHUNK_SIZE, fp);
		LOG_DEBUG("encrypting chunk of %d plaintext bytes\n", chunk_plainlen);

		// do encryption
		unsigned char *chunk_ciphertext;
		sc.encrypt(datachunk, chunk_plainlen);
		unsigned int chunk_cipherlen = sc.flush_ciphertext(&chunk_ciphertext);

		// hash partial ciphertext
		hc.hash(chunk_ciphertext, chunk_cipherlen);

		// send encrypted data
		LOG_DEBUG("sending chunk(%d) of %d bytes\n", i, chunk_cipherlen);
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
			LOG_DEBUG("sending padding of %d bytes\n", padding_cipherlen);

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
	LOG_DEBUG("client %d LIST_FILE\n",session_no);
	string path = "./files/";
	path += v_sess[session_no]->username;
	std::string s = show_dir_content(path.c_str()); 
	data_response = new char[s.length()+1];
	memcpy(data_response,s.c_str(),s.length()+1);

	if( !send_str_response(cl_sd, data_response, strlen(data_response)+1, session_no) )
		throw std::runtime_error("cannot send response");
}

void download_command_response(int cl_sd, unsigned session_no, download_file* dwn_header)
{
	if(dwn_header->filename_len > 255)
		throw std::runtime_error("Filename length is invalid");

	dwn_header->filename[dwn_header->filename_len] = '\0';

	string fname(dwn_header->filename);
	if( fname.find("..") != string::npos ){
		printf("[%u] Malicious client\n", session_no);
		send_file_response(cl_sd,"files/uwannafuckwithme",session_no);
		return ;
	}

	string path = "./files/";
	path += v_sess[session_no]->username;
	path += "/";
	path += dwn_header->filename;

	printf("[%u] Client requested file %s\n", session_no, path.c_str());
	if(!send_file_response(cl_sd, path.c_str(), session_no))
		printf("[%u] Client requested non-existent file %s\n", session_no, path.c_str());
	else
		printf("[%u] File %s download completed\n", session_no, path.c_str());
}


int handler_fun(int cl_sd, unsigned session_no){
	v_sess.push_back(new Session());

	try {
		printf("[%u] Connected new client\n", session_no);

		// 1) Get Client Nonce
		recv_hello_msg(cl_sd, session_no);

		// 2) Send Server Nonce
		send_hello_msg(cl_sd, session_no);

		// 3) Send Server verification infos
		// sign {client_nonce|server_nonce}_Kpub
		send_server_verification(cl_sd, session_no);

		// 4/5) Check Client identity / Send auth response
		// receive {client_nonce|session key|username|password}_Kpub
		// send authok or authfailed
		if ( !check_client_identity(cl_sd, session_no) )
		{
			printf("[%u] Client not authenticated!\n", session_no);
			throw runtime_error("client authentication exception");
		}

		printf("[%u] Client authenticated\n", session_no);

		while(true)
		{
			// 6) Receive Command / 7) Send Response
			// receive {seqnum|command_str}_Ksess | HMAC{{seqnum|command_str}_Ksess}_Ksess
			// send {seqnum|data_response}_Ksess | HMAC{{seqnum|data_response}_Ksess}_Ksess
			unsigned char *received_command = NULL;
			unsigned int received_command_len;
			if(!receive_command(cl_sd, &received_command, &received_command_len, session_no)){
				LOG_ERROR("[%u] Security error generated while receiving command\n", session_no);
				throw runtime_error("client authentication exception");
			}

			if( convert_to_host_order(received_command) == -1 ){
				LOG_ERROR("[%u] convert_to_host_order failed\n",session_no);
			}

			if(((simple_msg*)received_command)->t == LIST_FILE)
				list_command_response(cl_sd, session_no);
			else if(((simple_msg*)received_command)->t == DOWNLOAD_FILE)
				download_command_response(cl_sd, session_no, (download_file*)received_command);
			else if(((simple_msg*)received_command)->t == QUIT_SESSION)
			{
				LOG_ERROR("[%u] Client quits\n", session_no);
				break;
			}
		}
	} catch (net_exception& e) {
		LOG_ERROR("[%u] Catched net_exception: %s\n", session_no, e.getMessage().c_str());
	} catch (...) {
		LOG_ERROR("[%u] Catched general exception\n", session_no);
	}

	LOG_ERROR("[%u] Closing connection.\n", session_no);
	close(cl_sd);
	delete v_sess[session_no];

	return 0;
}

void close_all(int){
	printf(RESET);
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
	
	atexit([]{close_all(0);});
	//signal(SIGINT, close_all);

	if( !open_database(&database, "database.sqlite3") ) {
		LOG_ERROR("error: failed to open database\n");
		return -1;
	}

	sd = open_tcp_server(server_port);
	if( sd == -1 ){
		LOG_ERROR("Failed to start server!");
	}

	printf("Server started on 127.0.0.1:%u\n", server_port);

	while( 1 ) {
		int cl_sd = accept_tcp_server(sd,&conn);
		std::thread threadObj(handler_fun,cl_sd,n_sessions++);
		threadObj.detach();
	}

	return 0;
}