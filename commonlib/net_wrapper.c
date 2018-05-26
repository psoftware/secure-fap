#include "net_wrapper.h"


int open_tcp_server(uint16_t port)
{
	char ip_str[16];
	int sock = -1, ret=-1;
	struct sockaddr_in my_addr;

	ret = socket(AF_INET, SOCK_STREAM, 0);
	if( ret == -1 ) {
		printf("Impossibile aprire socket");
		return -1;
	}
	sock = ret;

	memset(&my_addr, 0, sizeof(struct sockaddr_in));
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(port);
	my_addr.sin_addr.s_addr = INADDR_ANY;   

	ret = bind(sock, (struct sockaddr*)&my_addr, sizeof(struct sockaddr_in));
	if( ret == -1 )
	{
		perror("Bind fallita\n");
		close(sock);
		return -1;
	}

	inet_ntop(AF_INET, &my_addr.sin_addr, ip_str, 16);

	//printf("Server aperto. ip:%s porta:%d\n",ip_str,port);
	ret = listen(sock, 10);
	
	if( ret == -1)
		return -1;
	else
		return sock;
}

int start_tcp_connection(const char* ip_str, uint16_t port)
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

int close_connection( ConnectionTCP *conn )
{
	return close(conn->socket);
}


int accept_tcp_server(int sock_serv, ConnectionTCP *conn)
{
	int sd;
	char ip_str[16];
	socklen_t len = sizeof(conn->cl_addr);
	/*printf("sto per accettare. len=%d \n",len);*/
	sd = accept(sock_serv, (struct sockaddr*)&conn->cl_addr, &len);
	if( sd == -1 ) {
		printf("Errore accept\n");
		return -1;
	}
	conn->socket = sd;

	inet_ntop(AF_INET, ((char*)&conn->cl_addr.sin_addr), ip_str, 16);
	return sd;
}

int send_data( int sockt, unsigned char* buf, uint32_t buf_len )
{
	uint32_t nbytes = htonl(buf_len);
	uint32_t bsend = 0;

     /*invia quanti byte contiene il messaggio(formato big endian)*/
	bsend = send(sockt, (void*)&nbytes, 4, 0);
      
	#ifdef DEBUG_NET_WRAPPER	
//	logg2 << "pacchetto nbytes mandati " << std::dec << (uint32_t)bsend << " B e vale " << std::dec << (uint32_t)len_nbytes;
	#endif

	if( bsend < 4 )  
	{
		printf("pacchetto {nbytes} ha dim %d\n",bsend);
		return -1;
	}

	bsend = send(sockt, (void*)buf, buf_len, 0);
	//sprintf("dim=%d mess=%s inviati=%d\n",buf_len,buf,bsend);

	//printf("buf_len %d\n",buf_len);
	if( bsend < buf_len )
		printf("pacchetto {buf} ha dim %d, inviati %d\n",buf_len,bsend);
	
	return bsend;
}

int recv_data(int sockt, my_buffer* my_buff)
{
	uint32_t nbytes = 0;
	uint32_t received = 0; 

	received = recv(sockt, (void*)&nbytes, 4, 0);

	if( received < 4 )
		return -1;
	
	nbytes = ntohl(nbytes);
	if( nbytes > my_buff->size )
	{
		if( my_buff->buf != NULL )
			free(my_buff->buf);
		my_buff->buf = (unsigned char*)malloc(nbytes);	
		my_buff->size = nbytes;
	}
	clear_my_buffer(my_buff);

	unsigned int total_received = 0;
	while( total_received != nbytes )
	{
		received = recv(sockt, my_buff->buf + total_received, nbytes - total_received, 0);
		if(received == 0)
			return -1;
		total_received += received;
	}

	return total_received;
}

void clear_my_buffer( my_buffer *myb )
{
	if( myb->size > 0 && myb->buf!=NULL )
		memset(myb->buf,0,myb->size);
}