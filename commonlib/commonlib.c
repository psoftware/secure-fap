#include "commonlib.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <fcntl.h>
#include <unistd.h>

void print_hex(unsigned char* buff, unsigned int size)
{
	printf("Printing %d bytes\n", size);
	for(unsigned int i=0; i<size; i++)
		printf("%02hx", *((unsigned char*)(buff + i)));
	printf("\n");
}

int initialize_server_socket(const char * bind_addr, int port)
{
	int ret_sock = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in my_addr;
	memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(port);
	inet_pton(AF_INET, bind_addr, &my_addr.sin_addr);

	if(bind(ret_sock, (struct sockaddr*)&my_addr, sizeof(my_addr)) == -1)
	{
		printf("Error %s\n", strerror(errno));
		return -1;
	}
	if(listen(ret_sock, 10) == -1)
	{
		printf("Error %s\n", strerror(errno));
		return -2;
	}

	return ret_sock;
}

int start_server_and_wait_client(const char* ip_addr, int port)
{
	int server_socket = initialize_server_socket(ip_addr, port);
	if(server_socket < 0)
	{
		printf("Error %s\n", strerror(errno));
		return 1;
	}

	printf("start_server: server in ascolto su %s:%d\n", ip_addr, port);

	// dobbiamo aspettare che il client si connetta
	struct sockaddr_in cl_addr;
	int my_len = sizeof(cl_addr);
	int connected_client_fd = accept(server_socket, (struct sockaddr*)&cl_addr, (socklen_t*)&my_len);
	printf("start_server: client connesso!\n");

	return connected_client_fd;
}

int recv_variable_string(int cl_sock, unsigned char * buff)
{
	//faccio una recv di un byte
	unsigned int bytes_count;
	int ret = recv(cl_sock, (void*)&bytes_count, sizeof(unsigned int), MSG_WAITALL);
	if(ret == 0 || ret == -1)
		return ret;

	bytes_count=ntohl(bytes_count);

	//faccio una recv di nbyte ricevuti dalla recv precedente
	ret = recv(cl_sock, (void*)buff, bytes_count, MSG_WAITALL);
	if(ret == 0 || ret == -1)
		return ret;
	if(ret < bytes_count)
	{
		printf("recv_variable_string: Byte ricevuti (%d) minori di quelli previsti!\n", ret);
		return -1;
	}

	//print_hex(buff, bytes_count);

	return bytes_count;
}

int start_tcp_connection(const char* ip_str, int port)
{
	// creo il socket TCP
	int sock_client = socket(AF_INET, SOCK_STREAM, 0);

	struct sockaddr_in srv_addr;
	memset(&srv_addr, 0, sizeof(srv_addr));
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = htons(port);
	inet_pton(AF_INET, ip_str, &srv_addr.sin_addr);
	
	// effettuo la connect al server indicato
	if(connect(sock_client, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) == -1)
	{
		perror("Connect fallita");
		return -1;
	}

	return sock_client;
}

int send_variable_string(int cl_sock, unsigned char * buff, int bytes_count)
{
	//faccio una send del numero di byte che devo spedire
	int net_bytes_count = htonl(bytes_count);
	int ret = send(cl_sock, (unsigned int*)&net_bytes_count, sizeof(unsigned int), 0);
	if(ret == 0 || ret == -1)
		return ret;

	//faccio una send per i bytes_count bytes da inviare
	ret = send(cl_sock, (void*)buff, bytes_count, 0);
	if(ret == 0 || ret == -1)
		return ret;
	if(ret < bytes_count)
	{
		printf("send_variable_string: Byte ricevuti (%d) minori di quelli previsti!\n", ret);
		return -1;
	}

	//print_hex(buff, bytes_count);

	return ret;
}