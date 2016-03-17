#include "Network_ipv4_recv.h"

int main()
{
	pcap_t *handle;
	char *device;
	char error_buffer[PCAP_ERRBUF_SIZE];

	device = pcap_lookupdev(error_buffer);

	handle = pcap_open_live(device, 65536, 1, 1000, error_buffer);

	pcap_loop(handle, NULL, ethernet_protocol_packet_callback, NULL);

	pcap_close(handle);
	return 0;
}