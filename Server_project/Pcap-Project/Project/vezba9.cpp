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

void packet_handler(unsigned char* user, const struct pcap_pkthdr* packet_header,const unsigned char* packet_data);
void sort_packets();
void send_packets();

unsigned char* packet_buffer[100];
pcap_t* device_handle_in, *device_handle_out;
static int packet_num = 0;

int main()
{
    int i=0;
    int device_number;
    int sentBytes;
	pcap_if_t* devices;
	pcap_if_t* device;
	char error_buffer [PCAP_ERRBUF_SIZE];
	unsigned int netmask;

	
	char filter_exp[] = "udp and ip src 192.168.0.20";
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
	// Open the capture file 
	/*
	if ((device_handle_in = pcap_open_offline("example.pcap",	// File name 
								error_buffer					// Error buffer
	   )) == NULL)
	{
		printf("\n Unable to open the file %s.\n", "example.pcap");
		return -1;
	}
	/**************************************************************/

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
	// Allocate a send queue 
	//queue_udp = pcap_sendqueue_alloc(256*1024);	// 256 kB

	/**************************************************************/
	// Fill the queue with the packets from the network
	pcap_loop(device_handle_in, 0, packet_handler, NULL);

	/**************************************************************/
	// Transmit the queue 
	// ...parameter “sync” tells if the timestamps must be respected (sync=1 (true) or sync=0 (false))

	Sleep(2000);

	//sort_packets();
	send_packets();

	/*
	if ((sentBytes = pcap_sendqueue_transmit(device_handle_out, queue_udp, 0)) < queue_udp->len)
	{
		printf("An error occurred sending the packets: %s. Only %d bytes were sent\n", pcap_geterr(device_handle_out), sentBytes);
	}
	*/
	/**************************************************************/
	// Free queues 
 	//pcap_sendqueue_destroy(queue_udp);
	/**************************************************************/

	/**************************************************************/
	// !!! IMPORTANT: remember to close the output adapter, otherwise there will be no guarantee that all the packets will be sent!
	pcap_close(device_handle_out);

	return 0;
}

// Callback function invoked by libpcap/WinPcap for every incoming packet
void packet_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	// Retrieve position of ethernet_header
	/*
	    ethernet_header* eh;
        eh = (ethernet_header*)packet_data;
    */
	// Check the type of next protocol in packet
	//if (ntohs(eh->type) == 0x800)	// Ipv4
	//{
		/*
		ip_header* ih;
        ih = (ip_header*)(packet_data + sizeof(ethernet_header));
		
		//if(ih->next_protocol == 17) // UDP
		//{
		udp_header* uh = (udp_header*)((unsigned char*)ih + 4 * (ntohs(ih->header_length)));

		int data_len = ntohs(uh->datagram_length) - sizeof(uh);
		unsigned char *data = (unsigned char*)((unsigned char*)uh + sizeof(udp_header));
		*/
		//unsigned char* send_packet_data = NULL;
		//u_long seq_num = (u_long)(*((unsigned char*)data));

		/*
		if (pcap_sendpacket(device_handle_out,packet_data, packet_header->len) == -1)
		{
			printf("Warning: The packet will not be sent.\n");
		}
		*/
		//}
	//}

	packet_buffer[packet_num] = new unsigned char[packet_header->len];
	int len = packet_header->len;

	for (int i = 0; i < len; i++) 
	{
		packet_buffer[packet_num][i] = packet_data[i];
	}
	packet_num++;
	printf("%d", packet_num);
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

	for (i = 0; i < packet_num-1; i++) 
	{
		{
			eh = (ethernet_header*)packet_buffer[i];
			ih = (ip_header*)(packet_buffer[i] + sizeof(ethernet_header));
			udp_header* uh = (udp_header*)((unsigned char*)ih + 4 * (ntohs(ih->header_length)));
			unsigned char *data = (unsigned char*)((unsigned char*)uh + sizeof(udp_header));
			u_long key = (u_long)(*data);
		}
		j = i - 1;
		{
			if (j != -1)
			{
				eh = (ethernet_header*)packet_buffer[j];
				ih = (ip_header*)(packet_buffer[j] + sizeof(ethernet_header));
				udp_header* uh = (udp_header*)((unsigned char*)ih + 4 * (ntohs(ih->header_length)));
				unsigned char *data = (unsigned char*)((unsigned char*)uh + sizeof(udp_header));
				u_long cmp = (u_long)(*data);
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
	
	ethernet_header* eh;
	ip_header* ih;
	udp_header* uh;
	//unsigned char *data;
	//u_long seq_num;
	//unsigned char flags = 0x00;
	
	unsigned char eh_tmp;
	unsigned char ih_tmp;


	for (i = 0; i < packet_num; i++)
	{
		
		eh = (ethernet_header*)packet_buffer[i];
		ih = (ip_header*)(packet_buffer[i] + sizeof(ethernet_header));
		uh = (udp_header*)((unsigned char*)ih + 4 * (ntohs(ih->header_length)));
		//data = (unsigned char*)((unsigned char*)uh + sizeof(udp_header));
		//*data = (unsigned char)((u_long)(*data));
		
		int j;

		for (j = 0; j < 6; j++)
		{
			eh_tmp = eh->dest_address[i];
			eh->dest_address[i] = eh->src_address[i];
			eh->src_address[i] = eh_tmp;
		}

		for (j = 0; j < 4; j++) 
		{
			ih_tmp = ih->dst_addr[i];
			ih->dst_addr[i] = ih->src_addr[i];
			ih->src_addr[i] = ih_tmp;
		}

		if (pcap_sendpacket(device_handle_out, packet_buffer[i], 4+sizeof(eh)+sizeof(ih)+sizeof(uh)) == -1)
		{
			printf("Warning: The packet will not be sent.\n");
		}
	}

}