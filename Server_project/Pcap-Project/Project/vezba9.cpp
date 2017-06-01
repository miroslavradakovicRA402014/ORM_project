// Include libraries
// We do not want the warnings about the old deprecated and unsecure CRT functions since these examples can be compiled under *nix as well
#ifdef _MSC_VER
	#define _CRT_SECURE_NO_WARNINGS
#else
#include <netinet/in.h>
#include <time.h>
#endif

#include <thread>
#include <condition_variable>
#include <mutex>
#include <pcap.h>
#include "protocol_headers.h"

using namespace std;

void packet_handler_wifi(struct pcap_pkthdr* packet_header, unsigned char* packet_data);
void packet_handler_eth(struct pcap_pkthdr* packet_header, unsigned char* packet_data);
//void sort_packets();
//void send_packet(ex_udp_datagram* rec_packet);
//void create_ex_udp_packet(ex_udp_datagram **udp_d, unsigned char **packet_d);

pcap_t* device_handle_in_wifi, *device_handle_in_eth;
//static int packet_num = 0;
static int packet_num_wifi_write = 0;
static int packet_num_eth_write = 0;
static int packet_num_wifi_read = 0;
static int packet_num_eth_read = 0;
ex_udp_datagram* packet_buffer_wifi[100];
ex_udp_datagram* packet_buffer_eth[100];
unsigned char* packet_wifi;
unsigned char* packet_eth;

thread *wifi_cap_thread;
thread *eth_cap_thread;
/*
enum WiFiAdapterRECV {YES_WIFI,NO_WIFI};
enum ETHAdapterRECV  {YES_ETH,NO_ETH};
*/
void wifi_thread_handle();
void eth_thread_handle();

condition_variable wifi_cv;
//condition_variable ph_wifi_cv;


condition_variable eth_cv;
//condition_variable ph_eth_cv;

/*
WiFiAdapterRECV recv_wifi = NO_WIFI;
ETHAdapterRECV recv_eth = NO_ETH;
*/

bool eth_wait = false;
bool wifi_wait = false;

int main()
{
    int i=0;
    int device_number[2];
    int sentBytes;
	pcap_if_t* devices;
	pcap_if_t* device[2];
	char error_buffer [PCAP_ERRBUF_SIZE];
	unsigned int netmask;

	struct pcap_pkthdr* packet_header_wifi;
	unsigned char* packet_data_wifi;

	struct pcap_pkthdr* packet_header_eth;
	unsigned char* packet_data_eth;
	
	char filter_exp[] = "ip src 10.81.2.44 and udp port 27015";
	struct bpf_program fcode;

	/**************************************************************/
	//Retrieve the device list on the local machine 
	if (pcap_findalldevs(&devices, error_buffer) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", error_buffer);
		return -1;
	}

	// Pick two device from the list
	for (int j = 0; j < 2; j++) 
	{
		for (device[j] = devices; device[j]; device[j] = device[j]->next)
		{
			printf("%d. %s", ++i, device[j]->name);
			if (device[j]->description)
				printf(" (%s)\n", device[j]->description);
			else
				printf(" (No description available)\n");
		}

		// Check if list is empty
		if (i == 0)
		{
			printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
			return -1;
		}

		// Print the list
		printf("Enter the output interface number (1-%d):", i);
		scanf("%d", &device_number[j]);

		if (device_number[j] < 1 || device_number[j] > i)
		{
			printf("\nInterface number out of range.\n");
			return -1;
		}

		// Select the first device...
		device[j] = devices;
		// ...and then jump to chosen devices
		for (i = 0; i < device_number[j] - 1; i++)
		{
			device[j] = device[j]->next;
		}
	}
	/**************************************************************/
	// Open the input adapter wifi
	if ((device_handle_in_wifi = pcap_open_live(device[0]->name, 65536, 0, 1000, error_buffer)) == NULL)
	{
		printf("\n Unable to open adapter %s.\n", device[0]->name);
		return -1;
	}
	// Open the output adapter
	if ((device_handle_in_eth = pcap_open_live(device[1]->name, 65536, 0, 1000, error_buffer)) == NULL)
	{
		printf("\n Unable to open adapter %s.\n", device[1]->name);
		return -1;
	}
	
	// Check the link layer. We support only Ethernet for simplicity.
	if(pcap_datalink(device_handle_in_wifi) != DLT_EN10MB || pcap_datalink(device_handle_in_eth) != DLT_EN10MB)
	{
		printf("\nThis program works only on Ethernet networks.\n");
		return -1;

	}
	
	for (int j = 0; j < 2; j++)
	{
		if (!device[j]->addresses->netmask)
			netmask = 0;
		else
			netmask = ((struct sockaddr_in *)(device[j]->addresses->netmask))->sin_addr.s_addr;
	}
	// Compile the filter    
	if (pcap_compile(device_handle_in_wifi, &fcode, filter_exp, 1, netmask) < 0 || pcap_compile(device_handle_in_eth, &fcode, filter_exp, 1, netmask) < 0)
	{
		printf("\n Unable to compile the packet filter. Check the syntax.\n");
		return -1;
	}

	// Set the filter
	if (pcap_setfilter(device_handle_in_wifi, &fcode) < 0 || pcap_setfilter(device_handle_in_eth, &fcode) < 0)
	{
		printf("\n Error setting the filter.\n");
		return -1;
	}
	
	wifi_cap_thread = new thread(wifi_thread_handle);
	eth_cap_thread = new thread(eth_thread_handle);

	/**************************************************************/	
	//pcap_loop(device_handle_in, 0, packet_handler, NULL);
	while (1) 
	{
		if (pcap_next_ex(device_handle_in_wifi, &packet_header_wifi, (const u_char**)&packet_data_wifi) == 1)
		{
			packet_handler_wifi(packet_header_wifi, packet_data_wifi);
			if (packet_num_wifi_read < packet_num_wifi_write && wifi_wait) 
			{
				wifi_cv.notify_one();
			}
		}
		else if (pcap_next_ex(device_handle_in_eth, &packet_header_eth, (const u_char**)&packet_data_eth) == 1) 
		{
			packet_handler_eth(packet_header_eth, packet_data_eth);
			if (packet_num_eth_read < packet_num_eth_write && eth_wait)
			{
				wifi_cv.notify_one();
			}
		}
	}
	/**************************************************************/


	wifi_cap_thread->detach();
	eth_cap_thread->detach();

	// !!! IMPORTANT: remember to close the output adapter, otherwise there will be no guarantee that all the packets will be sent!
	pcap_close(device_handle_in_wifi);
	pcap_close(device_handle_in_eth);

	return 0;
}
void wifi_thread_handle() 
{
	mutex mx;
	printf("WiFi thread \n");
	while (1)
	{
		unique_lock<mutex> l(mx);
		while (packet_num_wifi_read == packet_num_wifi_write)
		{
			wifi_wait = true;
			wifi_cv.wait(l);
		}

		wifi_wait = false;

		//Send packet
		int i;
		int j;

		ex_udp_datagram *udp_d;

		//printf("WiFi handle \n");

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

			pcap_next_ex(device_handle_i, &packet_header, (const u_char**)&packet_wifi);		
		}

		udp_d = new ex_udp_datagram(packet_wifi);

		udp_d->iph->length = htons(4 + 20 + sizeof(udp_header));
		udp_d->uh->datagram_length = htons(sizeof(udp_header) + 4);
		*(udp_d->seq_number) = *(packet_buffer_wifi[packet_num_wifi_read]->seq_number);
		udp_d->uh->dest_port = packet_buffer_wifi[packet_num_wifi_read]->uh->src_port;
		udp_d->uh->src_port = packet_buffer_wifi[packet_num_wifi_read]->uh->dest_port;

		udp_d->iph->ttl = htons(100);


		for (j = 0; j < 6; j++)
		{
			udp_d->eh->dest_address[j] = packet_buffer_wifi[packet_num_wifi_read]->eh->src_address[j];
			udp_d->eh->src_address[j] = packet_buffer_wifi[packet_num_wifi_read]->eh->dest_address[j];
		}

		for (j = 0; j < 4; j++)
		{
			udp_d->iph->dst_addr[j] = packet_buffer_wifi[packet_num_wifi_read]->iph->src_addr[j];
			udp_d->iph->src_addr[j] = packet_buffer_wifi[packet_num_wifi_read]->iph->dst_addr[j];
		}

		printf("Send ack from WiFi= %lu \n", (u_long)(*(udp_d->seq_number)));

		if (pcap_sendpacket(device_handle_in_wifi, packet_wifi, 4 + sizeof(ethernet_header) + 20 + sizeof(udp_header)) == -1)
		{
			printf("Warning: The packet will not be sent.\n");
		}

		packet_num_wifi_read++;
		//printf("WiFi handle end\n");

		//recv_wifi = (WiFiAdapterRECV)NO_WIFI;
		//ph_wifi_cv.notify_one();
	}
}

void packet_handler_wifi(struct pcap_pkthdr* packet_header, unsigned char* packet_data)
{
	//mutex mx;
	//unique_lock<mutex> l(mx);
	//while (recv_wifi == YES_WIFI)
	//	ph_wifi_cv.wait(l);

	ex_udp_datagram* rec_packet;
	rec_packet = new ex_udp_datagram(packet_header, packet_data);

	packet_buffer_wifi[packet_num_wifi_write] = rec_packet;
	int len = packet_header->len;

	packet_num_wifi_write++;

	printf("WiFi packet num recived = %d \n", packet_num_wifi_write);

	//recv_wifi = (WiFiAdapterRECV)YES_WIFI;
	//wifi_cv.notify_one();

}

void eth_thread_handle()
{
	mutex mx;
	printf("Eth thread \n");
	while (1)
	{
		unique_lock<mutex> l(mx);
		while (packet_num_eth_read == packet_num_eth_write) 
		{
			eth_wait = true;
			eth_cv.wait(l);
		}

		eth_wait = false;

		//Send packet
		int i;
		int j;

		ex_udp_datagram *udp_d;

		//printf("Eth handle \n");

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

			pcap_next_ex(device_handle_i, &packet_header, (const u_char**)&packet_eth);
		}

		udp_d = new ex_udp_datagram(packet_eth);

		udp_d->iph->length = htons(4 + 20 + sizeof(udp_header));
		udp_d->uh->datagram_length = htons(sizeof(udp_header) + 4);
		*(udp_d->seq_number) = *(packet_buffer_eth[packet_num_eth_read]->seq_number);
		udp_d->uh->dest_port = packet_buffer_eth[packet_num_eth_read]->uh->src_port;
		udp_d->uh->src_port = packet_buffer_eth[packet_num_eth_read]->uh->dest_port;

		udp_d->iph->ttl = htons(100);
		

		for (j = 0; j < 6; j++)
		{
			udp_d->eh->dest_address[j] = packet_buffer_eth[packet_num_eth_read]->eh->src_address[j];
			udp_d->eh->src_address[j] = packet_buffer_eth[packet_num_eth_read]->eh->dest_address[j];
		}

		for (j = 0; j < 4; j++)
		{
			udp_d->iph->dst_addr[j] = packet_buffer_eth[packet_num_eth_read]->iph->src_addr[j];
			udp_d->iph->src_addr[j] = packet_buffer_eth[packet_num_eth_read]->iph->dst_addr[j];
		}

		printf("Send ack from Eth= %lu \n", (u_long)(*(udp_d->seq_number)));

		if (pcap_sendpacket(device_handle_in_eth, packet_eth, 4 + sizeof(ethernet_header) + 20 + sizeof(udp_header)) == -1)
		{
			printf("Warning: The packet will not be sent.\n");
		}

		packet_num_eth_read++;
		//printf("Eth handle end \n");

		//recv_eth = (ETHAdapterRECV)NO_ETH;
		//ph_eth_cv.notify_one();
	}
}



// Callback function invoked by libpcap/WinPcap for every incoming packet
void packet_handler_eth(struct pcap_pkthdr* packet_header,unsigned char* packet_data)
{
	//mutex mx;
	//unique_lock<mutex> l(mx);
	//while (recv_eth == YES_ETH)
	//	ph_eth_cv.wait(l);

	ex_udp_datagram* rec_packet;
	rec_packet = new ex_udp_datagram(packet_header,packet_data);
	
	packet_buffer_eth[packet_num_eth_write] = rec_packet;
	int len = packet_header->len;

	packet_num_eth_write++;

	printf("Eth packet num recived= %d \n", packet_num_eth_write);

	//recv_eth = (ETHAdapterRECV)YES_ETH;
	//eth_cv.notify_one();
}

/*
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
			u_long *data = (u_long*)((unsigned char*)packet_buffer[i]+ sizeof(ethernet_header) + 20 +sizeof(udp_header));
			u_long key = (u_long)ntohs((*data));
		}
		j = i - 1;
		{
			if (j != -1)
			{
				u_long *data = (u_long*)((unsigned char*)packet_buffer[j] + sizeof(ethernet_header) + 20 + sizeof(udp_header));
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
*/
/*
void send_packet(ex_udp_datagram *rec_packet)
{
	int i;
	int j;

	ex_udp_datagram *udp_d;
	create_ex_udp_packet(&udp_d, &packet);
	udp_d = new ex_udp_datagram(packet);

	udp_d->iph->length = htons(4 + 20 + sizeof(udp_header));
	udp_d->uh->datagram_length = htons(sizeof(udp_header) + 4);
	*(udp_d->seq_number) = *(rec_packet->seq_number);
	udp_d->uh->dest_port = rec_packet->uh->src_port;
	udp_d->uh->src_port = rec_packet->uh->dest_port;

	udp_d->iph->ttl = htons(100);

        
	for (j = 0; j < 6; j++)
	{
		udp_d->eh->dest_address[j] = rec_packet->eh->src_address[j];
		udp_d->eh->src_address[j] = rec_packet->eh->dest_address[j];
	}

	for (j = 0; j < 4; j++)
	{
		udp_d->iph->dst_addr[j] = rec_packet->iph->src_addr[j];
		udp_d->iph->src_addr[j] = rec_packet->iph->dst_addr[j];
	}
	
	printf("Send ack= %lu \n", (u_long)(*(udp_d->seq_number)));

	if (pcap_sendpacket(device_handle_in_wifi, packet, 4+ sizeof(ethernet_header) + 20 + sizeof(udp_header)) == -1)
	{
		printf("Warning: The packet will not be sent.\n");
	}

}
*/
/*
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
}
*/