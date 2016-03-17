#include "Network_ipv4_recv.h"

int main()
{
	pcap_t *handle;
	char error_buffer[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list */
	pcap_if_t *d, *alldevs;
	if(pcap_findalldevs(&alldevs, error_buffer) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n",error_buffer);
		return 1;
	}
	
	/* Print the list */
	int i=0, inum=0;
	for(d = alldevs;d;d = d->next)
	{
		printf("%d.  %s\n", ++i, d->name);
		if(d->description)
			printf("   (%s)\n", d->description);
		else
			printf("   (No decription avalible)\n");
	}

	if(i == 0)
	{
		printf("\nNo interfaces found£¡Make sure Wincap is installed.\n");
		return -1;
	}

	printf("Enter the interface nuber (1-%d):",i);
	scanf("%d", &inum);
	if(inum < 1 || inum >i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for(d = alldevs, i=0; i< inum-1;d = d->next,i++);

	/*Open the adapter */
	if( (handle = pcap_open_live(d->name, //name of the device
		65536, // portion of the packet to capture.
		       // 65536 grants that the whole packet to capture.
			   // all the MACs.
		1, // promiscuous mode
		1000, //read timeout
		error_buffer // error buffer
		)) == NULL)
	{
		fprintf(stderr,"\nUnable to open adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Check the link layer. We support only Ethernet for simplicity. */
	if(pcap_datalink(handle)!= DLT_EN10MB)
	{
		fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	//handle = pcap_open_live(device, 65536, 1, 1000, error_buffer);

	while (true)
	{
		pcap_loop(handle, 1, ethernet_protocol_packet_callback, NULL);  
	}

	pcap_close(handle);
	pcap_freealldevs(alldevs);
	return 0;
}