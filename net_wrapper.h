#ifndef NET_WRAPPER_H
#define NET_WRAPPER_H	

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>

typedef struct my_buffer_t
{
	char* buf;
	uint32_t size;
}my_buffer;


typedef struct ConnectionTCP_t
{
	int socket;
	struct sockaddr_in cl_addr;
}ConnectionTCP;


/**Richiede numero di porta little endian**/
int open_serverTCP(uint16_t port);

/**restituisce id della socket che ha avuto la connessione*/
int accept_serverTCP(int sock_serv, ConnectionTCP *conn);


/********************************************************
* Riceve dati dalla socket indicata. La funzione negozia
* il numero di byte da ricevere ed alloca un buffer in cui
* depositare il messaggio. Il buffer verra' allocato nel
* my_buffer* passato come parametro. Riceve al max 4GiB
********************************************************/
int recv_data(int sockt, my_buffer* my_buff);

/*l'ultimo parametro dice quanti byte inviare (max 4GiB)*/
int send_data(int sockt, char* buf, uint32_t buf_len);

int close_connection(ConnectionTCP *conn);

void clear_my_buffer(my_buffer *myb);
#endif