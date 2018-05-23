#ifndef __COMMONLIB
#define __COMMONLIB

#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <dirent.h> 
#include <fcntl.h>
#include <unistd.h>
#include <string>
//#include <filesystem>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "messages.h"
#include "net_wrapper.h"


#define CHUNK_SIZE 32
#define HMAC_LENGTH 32

#include "EncryptSession.h"
#include "DecryptSession.h"
#include "SymmetricCipher.h"
#include "SignatureVerifier.h"
#include "SignatureMaker.h"
#include "DynamicArray.h"

/* ##### OpenSSL Help Functions ##### */;
void secure_zero(void *s, size_t n);

uint64_t generate_nonce();
void generate_session_key(unsigned char key[]);
void generate_iv(unsigned char iv[]);

bool compute_SHA256(void* input, unsigned long length, unsigned char* md);
void SHA1hash_to_string(unsigned char *hashbin, char *hashstr);

class HMACMaker {
private:
	HMAC_CTX* hmac_ctx;
	HMACMaker(const HMACMaker&);
public:
	HMACMaker(unsigned char *key, unsigned int key_length);

	unsigned int hash(unsigned char *partial_plaintext, unsigned int partial_plainlen);
	unsigned int hash_end(unsigned char **hash);

	~HMACMaker();
};

/* ##### OpenSSL Help Functions ##### */
unsigned int hmac_compute(
	unsigned char *inputdata[], unsigned int inputdata_length[], unsigned int inputdata_count,
	unsigned char *key, unsigned int key_length,
	unsigned char *hash_output);

// Utils
void print_hex(unsigned char* buff, unsigned int size);

unsigned int open_file_r(const char *filename, FILE **fp);
void open_file_w(const char *filename, FILE **fp);

// Server functions
int initialize_server_socket(const char * bind_addr, int port);
std::string show_dir_content(const char * path);
//std::string get_dir_content(std::string path); //C++17
bool recv_msg(int sd, void *s_msg, message_type expected);

#endif