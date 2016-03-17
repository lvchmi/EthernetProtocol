#include<stdio.h>
#include<stdlib.h>
#include<time.h>
#include<string.h>

#define HAVE_REMOTE
#define WPCAP
#include<pcap.h>
#include<WinSock2.h>

#pragma warning(disable:4996)

struct ethernet_header
{
	u_int8_t destination_mac[6];
	u_int8_t source_mac[6];
	u_int16_t ethernet_type;
};

//generate crc table
void generate_crc32_table();
//calculate crc
u_int32_t calculate_crc(u_int8_t *buffer, int len);

void ethernet_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content);
