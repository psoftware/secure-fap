#include "messages.h"

// conversioni host order <-------> network order per interi su 64bit
#define HTONLL(x) ((1==htonl(1)) ? (x) : (((uint64_t)htonl((x) & 0xFFFFFFFFUL)) << 32) | htonl((uint32_t)((x) >> 32)))
#define NTOHLL(x) ((1==ntohl(1)) ? (x) : (((uint64_t)ntohl((x) & 0xFFFFFFFFUL)) << 32) | ntohl((uint32_t)((x) >> 32)))

void convert_to_network_order( void* msg )
{
	message_type* m_t = (message_type*)msg;
	switch( *m_t ){
		case KEY_EXCHANGE:
		case KEY_CONFIRMATION_SERVER:
		case KEY_CONFIRMATION_CLIENT:
		case GENERIC_ERR:
		case AUTHENTICATION_OK:
		case AUTHENTICATION_FAILED:
		case LIST_FILE:
		case QUIT_SESSION:
			((simple_msg*)msg)->t = htonl(((simple_msg*)msg)->t);
			break;
		case CLIENT_AUTHENTICATION:
			((client_auth*)msg)->t = htonl(((client_auth*)msg)->t); /// PORCA MISERIA, PORCA MISERIA STASERA SE NON MI INCAZZO
			((client_auth*)msg)->total_ciphertext_size = htonl(((client_auth*)msg)->total_ciphertext_size);
			((client_auth*)msg)->username_length = htonl(((client_auth*)msg)->username_length);
			((client_auth*)msg)->password_length = htonl(((client_auth*)msg)->password_length);
			break;
		case CLIENT_HELLO:
		case SERVER_HELLO:
			((hello_msg*)msg)->t = htonl(((hello_msg*)msg)->t);
			((hello_msg*)msg)->nonce = HTONLL(((hello_msg*)msg)->nonce);
			break;
		case SEND_FILE:
			((send_file_msg*)msg)->t = htonl(((send_file_msg*)msg)->t);
			((send_file_msg*)msg)->chunk_size = htonl(((send_file_msg*)msg)->chunk_size);
			((send_file_msg*)msg)->chunk_number = htonl(((send_file_msg*)msg)->chunk_number);
			break;
		default:
			break;
	}
}

void convert_to_host_order( void* msg )
{
	/*il campo type dei messaggi viene convertito
	  nel formato host order prima dello switch */
	message_type* m_t = (message_type*)msg;
	*m_t = ntohl(*m_t);

	switch( *m_t ){
		case GENERIC_ERR:
		case KEY_EXCHANGE:
		case KEY_CONFIRMATION_SERVER:
		case KEY_CONFIRMATION_CLIENT:
		case AUTHENTICATION_OK:
		case AUTHENTICATION_FAILED:
		case LIST_FILE:
		case QUIT_SESSION:
			break;
		case CLIENT_AUTHENTICATION:
			((client_auth*)msg)->total_ciphertext_size = ntohl(((client_auth*)msg)->total_ciphertext_size);
			((client_auth*)msg)->username_length = ntohl(((client_auth*)msg)->username_length);
			((client_auth*)msg)->password_length = ntohl(((client_auth*)msg)->password_length);
			break;
		case CLIENT_HELLO:
		case SERVER_HELLO:
			((hello_msg*)msg)->nonce = NTOHLL(((hello_msg*)msg)->nonce);
			break;
		case SEND_FILE:
			((send_file_msg*)msg)->chunk_size = ntohl(((send_file_msg*)msg)->chunk_size);
			((send_file_msg*)msg)->chunk_number = ntohl(((send_file_msg*)msg)->chunk_number);
			break;
		default:
			break;
	}
}