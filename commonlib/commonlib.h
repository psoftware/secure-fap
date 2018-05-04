#ifndef __COMMONLIB
#define __COMMONLIB

typedef enum { false, true } bool;

#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <fcntl.h>
#include <unistd.h>

#define HMAC_LENGTH 32

/* ##### OpenSSL Help Functions ##### */
unsigned int hmac_compute(
	unsigned char *inputdata[], unsigned int inputdata_length[], unsigned int inputdata_count,
	unsigned char *key, unsigned int key_length,
	unsigned char *hash_output);

// Utils
void print_hex(unsigned char* buff, unsigned int size);

// Server functions
int initialize_server_socket(const char * bind_addr, int port);
int recv_variable_string(int cl_sock, unsigned char * buff);

// Client functions
int send_variable_string(int cl_sock, unsigned char * buff, int bytes_count);

#endif