#ifndef MESSAGES_H
#define MESSAGES_H
#include <arpa/inet.h>
//#define DEBUG
#define NAME_LEN 64

typedef enum 
{ 
	GENERIC_ERR,
	SERVER_HELLO,
	CLIENT_HELLO, 
	SERVER_QUIT,
} message_type;


#define INIT_WELCOME_MESS(id) {WELCOME_MESS, (id)};

typedef struct simple_msg_t
{
	message_type t;
}__attribute__((packed)) simple_msg;

typedef struct hello_msg_t
{
	message_type t;
	int32_t nonce;
}__attribute__((packed)) hello_msg;


/*******************************************
* Riconosce automaticamente il messaggio e
* lo converte nel network order
********************************************/
void convert_to_network_order( void* msg );

/*******************************************
* Riconosce automaticamente il messaggio e
* lo converte nell'host order
********************************************/
void convert_to_host_order( void* msg );


#endif