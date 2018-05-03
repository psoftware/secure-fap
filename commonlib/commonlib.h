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

// Utils
void print_hex(unsigned char* buff, unsigned int size);

// Server functions
int initialize_server_socket(const char * bind_addr, int port);
int start_server_and_wait_client(const char* ip_addr, int port);
int recv_variable_string(int cl_sock, unsigned char * buff);

// Client functions
int start_tcp_connection(const char* ip_str, int port);
int send_variable_string(int cl_sock, unsigned char * buff, int bytes_count);

#endif