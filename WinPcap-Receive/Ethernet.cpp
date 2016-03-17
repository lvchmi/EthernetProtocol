#include "Network_ipv4_recv.h"


u_int32_t crc32_table[256];
u_int8_t accept_dest_mac[2][6] = { { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 }, { 0x44, 0x37, 0xE6, 0x89, 0xCa, 0xf2 } };
u_int32_t packet_number = 1;

//generate table
void generate_crc32_table()
{
	int i, j;
	u_int32_t crc;
	for (i = 0; i < 256; i++)
	{
		crc = i;
		for (j = 0; j < 8; j++)
		{
			if (crc & 1)
				crc = (crc >> 1) ^ 0xEDB88320;
			else
				crc >>= 1;
		}
		crc32_table[i] = crc;
	}
}

u_int32_t calculate_crc(u_int8_t *buffer, int len)
{
	int i;
	u_int32_t crc;
	crc = 0xffffffff;
	for (i = 0; i < len; i++)
	{
		crc = (crc >> 8) ^ crc32_table[(crc & 0xFF) ^ buffer[i]];
	}
	crc ^= 0xffffffff;
	return crc;
}

int is_accept_ethernet_packet(u_int8_t *packet_content)
{
	int len = strlen((const char *)packet_content);
	struct ethernet_header *ethernet_hdr = (struct ethernet_header *)packet_content;
	int i, j;
	int flag;
	for (i = 0; i < 2; i++)
	{
		flag = i;
		for (j = 0; j < 6; j++)
		{
			if (ethernet_hdr->destination_mac[j] == accept_dest_mac[i][j])continue;
			else
			{
				flag = -1;
				break;
			}
		}
		if (flag == i)
		{
			return 1;
		}
	}
	if (flag == -1)
	{
		//printf("It's not acceptable mac.\n");
		return 0;
	}
	//crc match
	u_int32_t crc = calculate_crc((u_int8_t *)(packet_content + sizeof(ethernet_header)), len - 4 - sizeof(ethernet_header));
	if (crc != *((u_int32_t *)(packet_content + len - 4)))
	{
		printf("The data has changed.\n");
		return 0;
	}
	return 1;
}

//void output_time(time_t t)
//{
//	tm *local;
//	char buf[128] = { 0 };
//	local = localtime(&t);
//	strftime(buf, 64, "%Y-%M-%D %H:%M:%S", local);
//	printf("%s", buf);
//}

void output_mac(u_int8_t mac[6])
{
	for (int i = 0; i < 6; i++)
	{
		if (i)printf(":");
		printf("%02x", mac[i]);
	}
	printf("\n");
}

void ethernet_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)
{
	if (!is_accept_ethernet_packet((u_int8_t *)packet_content))
	{
		return;
	}

	struct ethernet_header *ethernet_hdr = (struct ethernet_header *)packet_content;
	u_int16_t ethernet_type = ntohs(ethernet_hdr->ethernet_type);
	int len = packet_header->len;

	printf("Capture %d packet\n", packet_number++);
	printf("Capture time: %d %d\n", packet_header->ts.tv_sec, packet_header->ts.tv_usec);
	//output_time(packet_header->ts.tv_sec);
	printf("Packet length: %d\n", packet_header->len);

	printf("--------------------------Ethernet Protocol------------------------\n");
	printf("Ethernet type:  %04x\n", ethernet_type);
	printf("MAC source address: ");
	output_mac(ethernet_hdr->source_mac);
	printf("MAC destination address: ");
	output_mac(ethernet_hdr->destination_mac);
	
	u_int8_t *ip_buffer = (u_int8_t *)(packet_content + sizeof(ethernet_header));

	switch (ethernet_type)
	{
	case 0x0800:
		printf("Upper layer protocol: IPV4\n");
		network_ipv4_recv(ip_buffer);
		break;
	case 0x0806:
		printf("Upper layer protocol: ICMPV4\n");
		//network_icmpv4_recv(icmpv4_buffer);
		break;
	case 0x8035:
		printf("Upper layer protocol: IGMPV4\n");
		//network_igmpv4_recv(igmpv4_buffer);
		break;
	case 0x814c:
		printf("Upper layer protocol: RARP\n");
		//network_rarp_recv(rarp);
		break;
	case 0x8137:
		printf("Upper layer protocol: IPX(Internet Packet Exchange)\n");
		//network_ipx_recv();
		break;
	case 0x86DD:
		printf("Upper layer protocol: IPV6\n");
		//network_ipv6_recv();
		break;
	default:break;
	}

	//printf("-------------------End of Ethernet Protocol----------------\n");
}