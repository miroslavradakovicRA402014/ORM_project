// Include libraries
// We do not want the warnings about the old deprecated and unsecure CRT functions since these examples can be compiled under *nix as well
#ifdef _MSC_VER
	#define _CRT_SECURE_NO_WARNINGS
#else
#include <netinet/in.h>
#include <time.h>
#endif

#include <pcap.h>
#include "protocol_headers.h"

void packet_handler(struct pcap_pkthdr* packet_header, unsigned char* packet_data);
void sort_packets();
void send_packets();
void create_ex_udp_packet(ex_udp_datagram **udp_d, unsigned char **packet_d);

pcap_t* device_handle_in, *device_handle_out;
static int packet_num = 0;
ex_udp_datagram* packet_buffer[10];

int main()
{
    int i=0;
    int device_number;
    int sentBytes;
	pcap_if_t* devices;
	pcap_if_t* device;
	char error_buffer [PCAP_ERRBUF_SIZE];
	unsigned int netmask;

	struct pcap_pkthdr* packet_header;
	unsigned char* packet_data;

	
	char filter_exp[] = "udp and ip src 10.81.2.48";
	struct bpf_program fcode;
	
	/**************************************************************/
	//Retrieve the device list on the local machine 
	if (pcap_findalldevs(&devices, error_buffer) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", error_buffer);
		return -1;
	}
	// Count devices and provide jumping to the selected device 
	// Print the list
	for(device=devices; device; device=device->next)
	{
		printf("%d. %s", ++i, device->name);
		if (device->description)
			printf(" (%s)\n", device->description);
		else
			printf(" (No description available)\n");
	}

	// Check if list is empty
	if (i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	// Pick one device from the list
	printf("Enter the output interface number (1-%d):",i);
	scanf("%d", &device_number);

	if(device_number < 1 || device_number > i)
	{
		printf("\nInterface number out of range.\n");
		return -1;
	}

	// Select the first device...
	device=devices;
	// ...and then jump to chosen devices
	for (i=0; i<device_number-1; i++)
	{
		device=device->next;
	}

	/**************************************************************/
	// Open the input adapter
	if ((device_handle_in = pcap_open_live(device->name, 65536, 0, 1000, error_buffer)) == NULL)
	{
		printf("\n Unable to open adapter %s.\n", device->name);
		return -1;
	}
	// Open the output adapter
	if ((device_handle_out = pcap_open_live(device->name, 65536, 0, 1000, error_buffer)) == NULL)
	{
		printf("\n Unable to open adapter %s.\n", device->name);
		return -1;
	}
	
	// Check the link layer. We support only Ethernet for simplicity.
	if(pcap_datalink(device_handle_in) != DLT_EN10MB || pcap_datalink(device_handle_out) != DLT_EN10MB)
	{
		printf("\nThis program works only on Ethernet networks.\n");
		return -1;
	}
	
	if (!device->addresses->netmask)
		netmask = 0;
	else
		netmask = ((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.s_addr;

	// Compile the filter    
	if (pcap_compile(device_handle_in, &fcode, filter_exp, 1, netmask) < 0)
	{
		printf("\n Unable to compile the packet filter. Check the syntax.\n");
		return -1;
	}

	// Set the filter
	if (pcap_setfilter(device_handle_in, &fcode) < 0)
	{
		printf("\n Error setting the filter.\n");
		return -1;
	}
	
	/**************************************************************/

	/**************************************************************/
	// Fill the queue with the packets from the network
	
	//pcap_loop(device_handle_in, 0, packet_handler, NULL);
	while (1) 
	{
		if (pcap_next_ex(device_handle_in, &packet_header, (const u_char**)&packet_data) == 1)
		{
			packet_handler(packet_header, packet_data);
		}
	}

	//sort_packets();

	/**************************************************************/

	// !!! IMPORTANT: remember to close the output adapter, otherwise there will be no guarantee that all the packets will be sent!
	pcap_close(device_handle_out);

	return 0;
}

// Callback function invoked by libpcap/WinPcap for every incoming packet
void packet_handler(struct pcap_pkthdr* packet_header,unsigned char* packet_data)
{
	ex_udp_datagram* rec_packet;
	rec_packet = new ex_udp_datagram(packet_header,packet_data);
	
	packet_buffer[packet_num] = new ex_udp_datagram(packet_header,packet_data);
	int len = packet_header->len;

	packet_num++;
	
	if (packet_num % 10 == 0) 
	{
		//printf("\n");
		send_packets();
	}	
	printf(" %d ", packet_num);
}

void sort_packets() 
{
	int i,j;
	ethernet_header* eh;
	ip_header* ih;
	udp_header* uh;
	unsigned char *data;
	u_long seq_num;
	u_long key,cmp;

	for (i = 0; i < BUFF_LEN; i++) 
	{
		{
			u_long *data = (u_long*)((unsigned char*)packet_buffer[i]+ sizeof(ethernet_header) + sizeof(ip_header) +sizeof(udp_header));
			u_long key = (u_long)ntohs((*data));
		}
		j = i - 1;
		{
			if (j != -1)
			{
				u_long *data = (u_long*)((unsigned char*)packet_buffer[j] + sizeof(ethernet_header) + sizeof(ip_header) + sizeof(udp_header));
				u_long cmp = (u_long)ntohs((*data));
			}
			else 
			{
				u_long cmp = -1;
			}
		}
		while (j >= -1 && cmp > key) 
		{
			packet_buffer[j + 1] = packet_buffer[j];
			j--;
		}
		packet_buffer[j + 1] = packet_buffer[i];
	}
}

void send_packets() 
{
	int i;
	u_long *seq_num;
	u_long tmp_seq_num;
	//unsigned char flags = 0x00;
	unsigned char* packet;
	
	unsigned char eh_tmp;
	unsigned char ih_tmp;


	for (i = 0; i < BUFF_LEN; i++)
	{
		seq_num = (u_long*)packet_buffer[i]->seq_number;
		tmp_seq_num = ntohs(*seq_num);
		printf("Send ack= %lu \n", (u_long)((*seq_num)));

		int j;
		ex_udp_datagram *udp_d;
		create_ex_udp_packet(&udp_d, &packet);

		udp_d->iph->length = 4 + sizeof(udp_header) + 20;
		udp_d->uh->datagram_length = sizeof(udp_header) + 4;
		udp_d->seq_number = 0;
		udp_d->eh = packet_buffer[i]->eh;
		udp_d->iph = packet_buffer[i]->iph;
		udp_d->uh = packet_buffer[i]->uh;
		udp_d->iph->ttl = 100;

        
		for (j = 0; j < 6; j++)
		{
			eh_tmp = udp_d->eh->dest_address[j];
			udp_d->eh->dest_address[j] = udp_d->eh->src_address[j];
			udp_d->eh->src_address[j] = eh_tmp;
		}

		for (j = 0; j < 4; j++)
		{
			ih_tmp = udp_d->iph->dst_addr[j];
			udp_d->iph->dst_addr[j] = udp_d->iph->src_addr[j];
			udp_d->iph->src_addr[j] = ih_tmp;
		}
	
		if (pcap_sendpacket(device_handle_in, packet, 4 + sizeof(ethernet_header) + 20 + sizeof(udp_header)) == -1)
		{
			printf("Warning: The packet will not be sent.\n");
		}

	}

}

void create_ex_udp_packet(ex_udp_datagram **ex_udp_d, unsigned char **packet_data)
{
	struct pcap_pkthdr* packet_header;
	pcap_t* device_handle_i;
	char error_buffer[PCAP_ERRBUF_SIZE];

	if ((device_handle_i = pcap_open_offline("udp.pcap",	// File name 
		error_buffer					// Error buffer
		)) == NULL)
	{
		printf("\n Unable to open the file %s.\n", "udp.pcap");
		return;
	}


	pcap_next_ex(device_handle_i, &packet_header, (const u_char**)packet_data);

	*ex_udp_d = new ex_udp_datagram(*packet_data);
}