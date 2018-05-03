#ifndef MESSAGES_H
#define MESSAGES_H
#include <arpa/inet.h>
//#define DEBUG
#define NAME_LEN 64

typedef enum 
{ 
	GENERIC_ERR,
	WELCOME_MESS, 
	PEER_SETS_NAME,
	PEER_SETS_UDP_PORT,
	NAME_ACCEPTED,
	NAME_REFUSED,
	REQ_LIST_OF_PEERS,
	RES_LIST_OF_PEERS,
	REQ_CONN_TO_PEER,
	REQ_CONN_FROM_PEER,
	PEER_DOES_NOT_EXIST,
	PEER_IS_NOT_FREE,
	CONN_TO_PEER_ACCEPTED,
	CONN_TO_PEER_REFUSED, 
	ACCEPT_CONN_FROM_PEER,
	REFUSE_CONN_FROM_PEER,
	SHIP_ARRANGED,
	SHOT_SHIP,
	SHIP_HIT,
	SHIP_MISS,
	YOU_WON,
	DISCONNECT_GAME,
	OPPONENT_DISCONNECTED,
	SERVER_QUIT,
} message_type;

/*
* - CONN_TO_PEER_REFUSED 
*   il sever risponde al mittente cha la
*   sua richiesta di connessione e' stata 
*   rifiutata.
*/

#define INIT_WELCOME_MESS(id) {WELCOME_MESS, (id)};
#define INIT_REG_SET_NAME { PEER_SETS_NAME, -1, {"\0"} }
#define INIT_REG_SET_UDP_PORT { PEER_SETS_UDP_PORT, 0, 0 }
#define INIT_REQ_CONN_FROM_PEER { REQ_CONN_FROM_PEER, -1, '\0' }
#define INIT_SHIP_HIT(col,row) { SHIP_HIT, (col), (row)};
#define INIT_SHIP_MISS(col,row) { SHIP_MISS, (col), (row)};


typedef struct simple_mess_t
{
	message_type t;
	int32_t peer_id;
}__attribute__((packed)) simple_mess;

typedef struct reg_set_name_t
{
	message_type t;
	int peer_id;
	char name[65];
}__attribute__((packed)) reg_set_name;

typedef struct reg_set_udp_port_t
{
	message_type t;
	int peer_id;
	uint16_t udp_port;
}__attribute__((packed))reg_set_udp_port;


/*******************************************
* Questo messaggio viene inviato  per gestire 
* le richieste di connessione da un peer ad
* un altro per iniziare una partita.
* Il messaggio ha nel campo t:
* - REQ_CONN_TO_PEER nel caso in cui il 
*   peer invia al server una richiesta di
*   connessione verso un altro peer.
* - REQ_CONN_FROM_PEER nel caso in cui il 
*   server inoltra al peer destinatario una
*   richiesta di connessione.
* - CONN_TO_PEER_ACCEPTED nel caso in cui
*   il server risponde al mittente che la
*   sua richiesta di connessione e' stata
*   accettata.	
* Nel primo caso il campo id identifica il
* peer mittente mentre il campo name indica
* il nome del destinatario.
* Nel secondo caso i campi id,name,udp_port,
* addr identificano il peer mittente.
* Nel terzo caso i campi id,name,udp_port,
* addr identificano il peer destinatario.
*******************************************/
typedef struct req_conn_peer_t
{
	message_type t;
	int32_t peer_id;
	char peer_name[65];
	struct sockaddr_in peer_addr; 
}__attribute__((packed)) req_conn_peer;


/*******************************************
* Questo messaggio viene inviato da un peer
* al server in risposta ad una richiesta di
* connessione. 
* t vale ACCEPT_CONN_FROM_PEER se il ricevitore
* della richiesta accetta la connessione.
* t vale REFUSE_CONN_FROM_PEER se il ricevitore
* della richiesta rifiuta la connessione.
* I due id sono utilizzati per identificare
* i peer in modo efficiente.
********************************************/
typedef struct response_conn_to_peer_t
{
	message_type t;
	int32_t peer_id;
	int32_t opponent_id;
}__attribute__((packed)) response_conn_to_peer;

/*******************************************
* Esempio:
* Il peer A vuole giocare con B
* A invia un messaggio req_conn_to_peer al
* server indicando nei campi   
*
********************************************/

typedef struct shot_mess_t 
{
	message_type t;
	char col;
	char row;
}__attribute__((packed)) shot_mess;

/*******************************************
* messaggio inviato dal server in risposta
* al comando !who inviato da un client.
* t: RES_LIST_OF_PEERS
* n_peer: quanti elementi contiene names
* names: vettore dei nomi dei peer connessi
* state: 0->libero, 1->occupato
********************************************/
typedef struct res_list_peers_t
{
	message_type t;
	uint32_t n_peer;
	struct peer_info_t {
		uint8_t state;
		char name[NAME_LEN+1];
	} peer_info[];
	
}__attribute__((packed)) res_list_peers;


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