#include "Network_IPV4_send.h"
#include "Resource.h"


u_int8_t buffer[MAX_SIZE];
u_int16_t ip_packet_id = 0;//as flag in ip_header->id
u_int32_t ip_size_of_packet = 0;

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

void load_ip_header(u_int8_t *ip_buffer)
{
	struct ip_header *ip_hdr = (struct ip_header*)ip_buffer;
	ip_size_of_packet = 0;
	//initial the ip header
	ip_hdr->version_hdrlen = 0x4f;//0100 1111 means ip version4 and header length: 60 bytes
	ip_hdr->type_of_service = 0xfe;/*111 1 1110: first 3 bits: priority level, 
								   then 1 bit: delay, 1 bit: throughput, 1 bit: reliability
								   1 bit: routing cost, 1 bit: unused
								   */
	ip_hdr->total_length = 0;// wait for data length, 0 for now
	ip_hdr->id = ip_packet_id;//identification
	ip_hdr->fragment_offset = 0x0000;/*0 0 0 0 00...00: first 3 bits is flag: 1 bit: 0 the last fragment,
								   1 more fragmet. 1 bit: 0 allow fragment, 1 don't fragment. 1 bit: unused
								   the last 12 bits is offset
								   */
	ip_hdr->time_to_live = 64;//default 1000ms
	ip_hdr->upper_protocol_type = IPPROTO_TCP;//default upper protocol is tcp
	ip_hdr->check_sum = 0;//initial zero

	ip_hdr->source_ip.s_addr = inet_addr("10.20.2.75");//convert ip string to a unsigned long 
	ip_hdr->destination_ip.s_addr = inet_addr("255.255.255.255");

	//initial check_sum is associate with offset. so in the data we need to calculate check_sum
	ip_size_of_packet += sizeof(ip_header);
}

void load_ip_data(u_int8_t *ip_buffer, FILE *fp, int len)
{
	int i = 0;
	char ch;
	while (i < len && (ch = fgetc(fp)) != EOF)
	{
		*(ip_buffer + i) = ch;
		i++;
	}
	ip_size_of_packet += len;
}

int network_ipv4_send(u_int8_t *ip_buffer, FILE *fp)
{
	//get the size of file
	int file_len;
	fseek(fp, 0, SEEK_END);
	file_len = ftell(fp);
	rewind(fp);

	//get how many fragments
	int number_of_fragment = (int)ceil(file_len*1.0 / MAX_IP_PACKET_SIZE);
	u_int16_t offset = 0;
	int ip_data_len;
	u_int16_t fragment_offset;
	while (number_of_fragment)
	{
		load_ip_header(ip_buffer);
		struct ip_header *ip_hdr = (struct ip_header *)ip_buffer;
		if (number_of_fragment == 1)
		{
			fragment_offset = 0x0000;//16bits
			ip_data_len = file_len - offset;
		}
		else
		{
			fragment_offset = 0x2000;//allow the next fragment
			ip_data_len = MAX_IP_PACKET_SIZE;
		}
		
        fragment_offset |= ((offset / 8) & 0x1fff);
		ip_hdr->fragment_offset = htons(fragment_offset);

		//printf("%04x\n", ip_hdr->fragment_offset);
		ip_hdr->total_length = htons(ip_data_len + sizeof(ip_header));
		ip_hdr->check_sum = calculate_check_sum(ip_hdr, 60);
		//printf("%04x\n", ip_hdr->check_sum);
        
		load_ip_data(ip_buffer + sizeof(ip_header), fp, ip_data_len);

		ethernet_send_packet(ip_buffer, buffer, ip_size_of_packet); //打包为数据帧格式并发送

		offset += MAX_IP_PACKET_SIZE;
		number_of_fragment--;
	}

	//auto increase one
	ip_packet_id++;

	return 1;
}




