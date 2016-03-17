#include "Ethernet.h"

//#define MAX_IP_PACKET_SIZE 1400
//
//u_int8_t ip_buffer[MAX_SIZE];
//u_int16_t ip_packet_id = 0;

struct ip_header
{
	u_int8_t version_hdrlen;// default IP version: ipv4, header_length: 60bytes
	u_int8_t type_of_service;//
	u_int16_t total_length;//
	u_int16_t id;			//identification
	u_int16_t fragment_offset;//packet maybe need to be fraged. 
	u_int8_t time_to_live; 
	u_int8_t upper_protocol_type;
	u_int16_t check_sum;

	struct in_addr source_ip;   //this is a structure equval to u_int32_t, but canbe used in windows socket api
	struct in_addr destination_ip;

	u_int8_t optional[40];//40 bytes is optional

};

u_int16_t calculate_check_sum(ip_header *ip_hdr, int len);

void load_ip_header(u_int8_t *ip_buffer);
int load_ip_data(u_int8_t *ip_buffer, u_int8_t *pkt_data, int len);

/*
send ip packet
call ethernet function to make a complete packet
*/
int network_ipv4_send(u_int8_t *ip_buffer, FILE *fp);

