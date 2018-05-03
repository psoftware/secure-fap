#include "messages.h"

void convert_to_network_order( void* msg )
{
	message_type* m_t = (message_type*)msg;
	switch( *m_t ){
		case CLIENT_HELLO:
		case SERVER_HELLO:
		case GENERIC_ERR:
		case SERVER_QUIT:
			((simple_mess*)msg)->t = htonl(((simple_mess*)msg)->t);
			((simple_mess*)msg)->peer_id = htonl(((simple_mess*)msg)->peer_id);
			break;
		
/*		case PEER_SETS_UDP_PORT:
			((reg_set_udp_port*)msg)->t = htonl(((reg_set_udp_port*)msg)->t);
			((reg_set_udp_port*)msg)->peer_id = htonl(((reg_set_udp_port*)msg)->peer_id);
			((reg_set_udp_port*)msg)->udp_port = htons(((reg_set_udp_port*)msg)->udp_port);
			break;
		
		case NAME_ACCEPTED:
		case NAME_REFUSED:
		case PEER_DOES_NOT_EXIST:
		case PEER_IS_NOT_FREE:
		case CONN_TO_PEER_REFUSED:
		case SERVER_QUIT:
		case OPPONENT_DISCONNECTED:
		case SHIP_ARRANGED:
		case SHOT_SHIP:
		case SHIP_HIT:
		case SHIP_MISS:
		case YOU_WON:
			*m_t = htonl(*m_t);
			break;
	
		case ACCEPT_CONN_FROM_PEER:
		case REFUSE_CONN_FROM_PEER:
			((response_conn_to_peer*)msg)->t = htonl(((response_conn_to_peer*)msg)->t);
			((response_conn_to_peer*)msg)->peer_id = htonl(((response_conn_to_peer*)msg)->peer_id);
			((response_conn_to_peer*)msg)->opponent_id = htonl(((response_conn_to_peer*)msg)->opponent_id);
			break;
	
		case RES_LIST_OF_PEERS:
			((res_list_peers*)msg)->t = htonl(((res_list_peers*)msg)->t);
			((res_list_peers*)msg)->n_peer = htonl(((res_list_peers*)msg)->n_peer);
			break;
*/
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
		case CLIENT_HELLO:
		case SERVER_HELLO:
		case GENERIC_ERR:
		case SERVER_QUIT:
			((simple_mess*)msg)->peer_id = ntohl(((simple_mess*)msg)->peer_id);
			break;
		
		/*case PEER_SETS_UDP_PORT:
			((reg_set_udp_port*)msg)->peer_id = ntohl(((reg_set_udp_port*)msg)->peer_id);
			((reg_set_udp_port*)msg)->udp_port = ntohs(((reg_set_udp_port*)msg)->udp_port);
			break;

		case ACCEPT_CONN_FROM_PEER:
		case REFUSE_CONN_FROM_PEER:
			((response_conn_to_peer*)msg)->peer_id = ntohl(((response_conn_to_peer*)msg)->peer_id);
			((response_conn_to_peer*)msg)->opponent_id = ntohl(((response_conn_to_peer*)msg)->opponent_id);
			break;
	
		case RES_LIST_OF_PEERS:
			((res_list_peers*)msg)->n_peer = ntohl(((res_list_peers*)msg)->n_peer);
			break;
		*/	
		default:
			break;
	}
}