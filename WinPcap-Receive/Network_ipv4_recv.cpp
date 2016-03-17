#include "Network_ipv4_recv.h"

#define MAX_DATA_SIZE 1000000
char *accept_ip[2] = { {"255.255.255.255"}, {"10.13.80.30"} };
u_int16_t ip_id = 0;
u_int16_t i = 0;

u_int8_t buffer[MAX_DATA_SIZE];

int previous = 0, current = 0;

/*
if allow fragment, store to buffer until not allow, then 
store to file.
*/

u_int16_t calculate_check_sum(ip_header *ip_hdr, int len)
{
	int sum = 0, tmp = len;
	u_int16_t *p = (u_int16_t*)ip_hdr;
	while (len > 1)
	{
		sum += *p;
		len -= 2;
		p++;
	}

	//len=1 last one byte
	if (len)
	{
		sum += *((u_int8_t*)ip_hdr + tmp - 1);
	}

	//fold 32 bits to 16 bits
	while (sum >> 16)
	{
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return ~sum;
}


int is_accept_ip_packet(struct ip_header *ip_hdr)
{
	char *destination_ip = inet_ntoa(ip_hdr->destination_ip);//this function translate the u_int32_t to char *
	if (strcmp(destination_ip, accept_ip[1]) == 0) //change
	{ 
		//printf("It's broadcast.\n");
	}
	else if (strcmp(destination_ip, accept_ip[1]) == 0)
	{
		//printf("It's sended to my pc\n");
	}
	else
	{
		printf("It's not acceptable ip\n");
		return 0;
	}

	u_int16_t check_sum = calculate_check_sum(ip_hdr, 60);
	if (check_sum == 0xffff || check_sum == 0x0000)
	{
		printf("No error in ip_header.\n");
	}
	else
	{
		printf("Error in ip_header\n");
		//network_icmpv4_recv(icmpv4_buffer);
		return 0;
	}
	if(ip_hdr->time_to_live == 0)
	{
		printf("TTL =0");
		//network_icmpv4_recv(icmpv4_buffer);
		return 0;
	 }
}



void load_data_to_buffer(u_int8_t *buffer, u_int8_t *ip_data, int len)
{
	int i;
	for (i = 0; i < len; i++)
	{
		*(buffer + i) = *(ip_data + i);
	}
}

int load_data_to_file(u_int8_t *buffer, int len, FILE *fp)
{
	int res = fwrite(buffer, sizeof(u_int8_t), len, fp);
	if (res != len)
	{
		//printf("Write file error!\n");
		return 0;
	}
	fflush(fp);
	return 1;
}


int network_ipv4_recv(u_int8_t *ip_buffer)
{
	struct ip_header *ip_hdr = (struct ip_header *)ip_buffer;
	int len = ntohs(ip_hdr->total_length) - sizeof(ip_header);


	//check the valid
	if (!is_accept_ip_packet(ip_hdr))
	{
		printf("ip is wrong!\n");
		return 0;
	}

	u_int16_t fragment;
	fragment = ntohs(ip_hdr->fragment_offset);
	
	int dural = 0;
	if (previous == 0)
	{
		previous = time(NULL);
	}
	else
	{
		//get current time
		current = time(NULL);
		dural = current - previous;
		printf("%d %d\n", current, previous);
		//current time became previous
		previous = current;
	}

	//interval can not larger than 30s
	if (dural >= 30)
	{
		printf("Time Elapsed.\n");
		return 0;
	}

	if ((fragment & 0x2000) && (ip_id == ip_hdr->id))//true means more fragment
	{
		load_data_to_buffer(buffer + i, ip_buffer + sizeof(ip_header), len);
		i += len;
		return 1;
	}
	else if (ip_id == ip_hdr->id)
	{
		load_data_to_buffer(buffer + i, ip_buffer + sizeof(ip_header), len);
		i += len;
		FILE *fp = fopen("data.txt", "w");
		if (load_data_to_file(buffer, i, fp))
		{
			//printf("Load to file Succeed.\n");
		}
		fclose(fp);
		//restore the value
		i = 0;
		ip_id++;
	}
	else
	{
		//printf("Lost packets.\n");
		//pass the last fragment make move
		i = 0;
		ip_id++;
		return 0;
	}

	printf("--------------IP Protocol-------------------\n");
	printf("IP version: %d\n", (ip_hdr->version_hdrlen & 0xf0));
	printf("Type of service: %02x\n", ip_hdr->type_of_service);
	printf("IP packet length: %d\n", len + sizeof(ip_header));
	printf("IP identification: %d\n", ip_hdr->id);
	printf("IP fragment & offset: %04x\n", ntohs(ip_hdr->fragment_offset));
	printf("IP time to live: %d\n", ip_hdr->time_to_live);
	printf("Upper protocol type: %02x\n", ip_hdr->upper_protocol_type);
	printf("Check sum: %04x\n", ip_hdr->check_sum);
	printf("Source IP: %s\n", inet_ntoa(ip_hdr->source_ip));
	printf("Destination IP: %s\n", inet_ntoa(ip_hdr->destination_ip));

	u_int8_t upper_protocol_type = ip_hdr->upper_protocol_type;
	switch (upper_protocol_type)
	{
	case IPPROTO_TCP:
		//transport_tcp_recv(tcp_buffer);
		break;
	case IPPROTO_UDP:
		//transport_udp_recv(udp_buffer);
		break;
	}

	printf("-----------------End of IP Protocol---------------\n");

}