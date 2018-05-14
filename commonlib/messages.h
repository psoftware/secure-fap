#ifndef MESSAGES_H
#define MESSAGES_H
#include <arpa/inet.h>
#include <stdio.h>
//#define DEBUG

typedef enum 
{ 
	GENERIC_ERR,
	SERVER_HELLO,
	CLIENT_HELLO, 
	KEY_EXCHANGE,
	KEY_CONFIRMATION_SERVER,
	KEY_CONFIRMATION_CLIENT,
	CLIENT_AUTHENTICATION,
	AUTHENTICATION_OK,
	AUTHENTICATION_FAILED,
	LIST_FILE,
	SEND_FILE,
	DOWNLOAD_FILE,
	QUIT_SESSION,
} message_type;


#define INIT_WELCOME_MESS(id) {WELCOME_MESS, (id)};

typedef struct simple_msg_t
{
	message_type t;
}__attribute__((packed)) simple_msg;

typedef struct hello_msg_t
{
	message_type t;
	uint64_t nonce; 
}__attribute__((packed)) hello_msg;

typedef struct client_auth_t
{
	message_type t;
	uint32_t total_ciphertext_size;
	uint32_t username_length;
	uint32_t password_length;
}__attribute__((packed)) client_auth;

typedef struct send_file_msg_t
{
	message_type t;
	uint8_t response_code;
	uint32_t chunk_size;
	uint32_t chunk_number;
}__attribute__((packed)) send_file_msg;

typedef struct download_file_t
{
	message_type t;
	char filename[256];	//for most of file systems this is the max filename length
	uint8_t filename_len;
}__attribute__((packed)) download_file;

#ifdef __cplusplus
extern "C" {
#endif
/*******************************************
* Riconosce automaticamente il messaggio e
* lo converte nel network order
********************************************/
void convert_to_network_order( void* msg );

/*******************************************
* Riconosce automaticamente il messaggio e
* lo converte nell'host order
********************************************/
int convert_to_host_order( void* msg );

#ifdef __cplusplus
}
#endif

#endif