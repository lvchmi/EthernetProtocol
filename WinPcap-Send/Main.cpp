#include "Network_IPV4_send.h"
#include "Resource.h"

u_int8_t ip_buffer[MAX_SIZE];

int main()
{
	//open file
	FILE *fp;
	fp = fopen("data.txt", "rb");
	if (fp==NULL)
	{
		printf("fp is null\n");
		return -1;
	}
	network_ipv4_send(ip_buffer, fp);
	fclose(fp);
	return 0;
}