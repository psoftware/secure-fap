#include "commonlib.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <fcntl.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>


void print_hex(unsigned char* buff, unsigned int size)
{
	printf("Printing %d bytes\n", size);
	for(unsigned int i=0; i<size; i++)
		printf("%02hx", *((unsigned char*)(buff + i)));
	printf("\n");
}

unsigned int open_file_r(const char *filename, FILE **fp)
{
	unsigned int fsize;

	*fp = fopen(filename, "r");
	if(*fp) {
		fseek(*fp, 0, SEEK_END);
		fsize = ftell(*fp);
		rewind(*fp);
	}
	else {
		perror("open_file: file doesn't exist\n");
		return 0;
	}

	return fsize;
}

void open_file_w(const char *filename, FILE **fp)
{
	*fp = fopen(filename, "w");
	if(!(*fp)) {
		perror("open_file: can't create file\n");
		return;
	}
}

/* ##### OpenSSL Help Functions ##### */

uint64_t generate_nonce()
{
	uint64_t nonce;
	RAND_bytes((unsigned char*)&nonce,8);
	return nonce;
}

void generate_session_key(unsigned char key[])
{
	RAND_bytes(key, 16);
}

void generate_iv(unsigned char iv[])
{
	RAND_bytes(iv, 16);
}

bool compute_SHA256(void* input, unsigned long length, unsigned char* md)
{
	SHA256_CTX context;
	if(!SHA256_Init(&context))
		return false;

	if(!SHA256_Update(&context, (unsigned char*)input, length))
		return false;

	if(!SHA256_Final(md, &context))
		return false;

	return true;
}

void SHA1hash_to_string(unsigned char *hashbin, char *hashstr) {
	for(int i = 0; i<32; i++)
		sprintf(&hashstr[i*2], "%02x", hashbin[i]);
	hashstr[64]='\0';
}

HMACMaker::HMACMaker(unsigned char *key, unsigned int key_length)
{
	hmac_ctx = new HMAC_CTX;
	HMAC_CTX_init(hmac_ctx);

	// init HMAC (using sha256)
	HMAC_Init(hmac_ctx, key, key_length, EVP_sha256());
}

unsigned int HMACMaker::hash(unsigned char *partial_plaintext, unsigned int partial_plainlen)
{
	HMAC_Update(hmac_ctx, partial_plaintext, partial_plainlen);
}

unsigned int HMACMaker::hash_end(unsigned char **hash)
{
	*hash = new unsigned char[HMAC_LENGTH];
	unsigned int outlen;
	HMAC_Final(hmac_ctx, *hash, &outlen);

	return outlen;
}

HMACMaker::~HMACMaker()
{
	HMAC_CTX_cleanup(hmac_ctx);
	delete hmac_ctx;
}

bool recv_msg(int sd, void *s_msg, message_type expected)
{
	my_buffer my_buff = {NULL, 0};
	int bytes_rec = recv_data(sd, &my_buff);
	memcpy(s_msg,my_buff.buf,bytes_rec);
	int t = convert_to_host_order(s_msg);
	printf("expected:%d received:%d \n",expected,t);
	if( t == expected )
		return true;
	else 
		return false;
}

#define NORMAL_COLOR  "\x1B[0m"
#define GREEN  "\x1B[32m"
#define BLUE  "\x1B[34m"


/* let us make a recursive function to print the content of a given folder */

void show_dir_content(const char * path)
{
  DIR * d = opendir(path); // open the path
  if(d==NULL) return; // if was not able return
  struct dirent * dir; // for the directory entries
  while ((dir = readdir(d)) != NULL) // if we were able to read somehting from the directory
    {
      if(dir-> d_type != DT_DIR) // if the type is not directory just print it with blue
        printf("%s%s\n",BLUE, dir->d_name);
      else
      if(dir -> d_type == DT_DIR && strcmp(dir->d_name,".")!=0 && strcmp(dir->d_name,"..")!=0 ) // if it is a directory
      {
        printf("%s%s\n",GREEN, dir->d_name); // print its name in green
        char d_path[255]; // here I am using sprintf which is safer than strcat
        sprintf(d_path, "%s/%s", path, dir->d_name);
        show_dir_content(d_path); // recall with the new path
      }
    }
    closedir(d); // finally close the directory
}