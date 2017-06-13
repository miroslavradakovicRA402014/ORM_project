// Include libraries
// We do not want the warnings about the old deprecated and unsecure CRT functions since these examples can be compiled under *nix as well
#ifdef _MSC_VER
	#define _CRT_SECURE_NO_WARNINGS
#else
#include <netinet/in.h>
#include <time.h>
#endif

#include "Functions.h"
using namespace std;

void packet_handler_wifi(struct pcap_pkthdr* packet_header, unsigned char* packet_data);
void packet_handler_eth(struct pcap_pkthdr* packet_header, unsigned char* packet_data);
void sort_packets(ex_udp_datagram* packet_buffer[], int buff_len);
void merge_packets();
void reconstruct_message();

pcap_t* device_handle_in_wifi, *device_handle_in_eth;
static int packet_num = 0;
static int packet_num_wifi_write = 0;
static int packet_num_eth_write = 0;
static int packet_num_wifi_read = 0;
static int packet_num_eth_read = 0;
static unsigned int total_size = MAX_LEN;
ex_udp_datagram* packet_buffer_wifi[MAX_LEN];
ex_udp_datagram* packet_buffer_eth[MAX_LEN];
ex_udp_datagram* packet_buffer[MAX_LEN];
unsigned char* packet_wifi;
unsigned char* packet_eth;
unsigned char* message;


thread *wifi_cap_thread;
thread *eth_cap_thread;
thread *sniff_thread;

void wifi_thread_handle();
void eth_thread_handle();
void catch_packets();

condition_variable wifi_cv;
condition_variable eth_cv;

bool eth_wait = false;
bool wifi_wait = false;

unsigned char server_eth_addr[6] = { 0x78, 0x0c, 0xb8, 0xf7, 0x71, 0xa0 };
//unsigned char source_eth_addr[6] = { 0x00, 0xe0, 0x4c, 0x36, 0x33, 0xf6 };
unsigned char client_eth_addr[6] = { 0x2c, 0xd0, 0x5a, 0x90, 0xba, 0x9a };
//unsigned char dest_eth_addr[6] = { 0x7c, 0x05, 0x07, 0x24, 0xf8, 0x04 };

unsigned char server_ip_addr[4] = { 192, 168, 0, 14 };
//unsigned char source_ip_addr[4] = { 169, 254, 176, 100 };
unsigned char client_ip_addr[4] = { 192, 168, 0, 10 };
//unsigned char dest_ip_addr[4] = { 169, 254, 176, 101 };

struct pcap_pkthdr* packet_header_wifi;
unsigned char* packet_data_wifi;

struct pcap_pkthdr* packet_header_eth;
unsigned char* packet_data_eth;

unsigned char *ack_packet_wifi;
unsigned char *ack_packet_eth;

ex_udp_datagram *rec_wifi_udp_d;
ex_udp_datagram *rec_eth_udp_d;

int main()
{
    int i=0;
    int device_number[2];
    int sentBytes;
	pcap_if_t* devices;
	pcap_if_t* device[2];
	char error_buffer [PCAP_ERRBUF_SIZE];
	unsigned int netmask;

	char filter_exp[] = "ip src 192.168.0.14 and udp port 27015";
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

	initialize(&packet_header_wifi, &packet_data_wifi);
	initialize(&packet_header_eth, &packet_data_eth);
	make_ack_packet(&ack_packet_wifi, packet_data_wifi, packet_header_wifi, PORT_NUMBER);
	make_ack_packet(&ack_packet_eth, packet_data_wifi, packet_header_wifi, PORT_NUMBER);
	set_addresses(&ack_packet_wifi, 1, client_eth_addr, server_eth_addr, client_ip_addr, server_ip_addr);
	set_addresses(&ack_packet_eth, 1, client_eth_addr, server_eth_addr, client_ip_addr, server_ip_addr);

	rec_wifi_udp_d = new ex_udp_datagram(ack_packet_wifi);
	rec_eth_udp_d = new ex_udp_datagram(ack_packet_eth);

	rec_wifi_udp_d->iph->checksum = ip_checksum(rec_wifi_udp_d->iph, rec_wifi_udp_d->iph->header_length * 4);
	rec_eth_udp_d->iph->checksum = ip_checksum(rec_eth_udp_d->iph, rec_eth_udp_d->iph->header_length * 4);
	
	wifi_cap_thread = new thread(wifi_thread_handle);
	eth_cap_thread = new thread(eth_thread_handle);
	sniff_thread = new thread(catch_packets);

	/**************************************************************/	
	//pcap_loop(device_handle_in, 0, packet_handler, NULL);
	/**************************************************************/

	wifi_cap_thread->detach();
	eth_cap_thread->detach();
	sniff_thread->join();
	
	reconstruct_message();

	delete [] message;

	// !!! IMPORTANT: remember to close the output adapter, otherwise there will be no guarantee that all the packets will be sent!
	pcap_close(device_handle_in_wifi);
	pcap_close(device_handle_in_eth);

	return 0;
}

void catch_packets() 
{
	printf("Sniff thread created\n");
	while (1)
	{
		if (pcap_next_ex(device_handle_in_wifi, &packet_header_wifi, (const u_char**)&packet_data_wifi) == 1)
		{
			packet_num++;
			packet_handler_wifi(packet_header_wifi, packet_data_wifi);
			if (packet_num_wifi_read < packet_num_wifi_write && wifi_wait)
			{
				wifi_cv.notify_one();
			}
		}
		else if (pcap_next_ex(device_handle_in_eth, &packet_header_eth, (const u_char**)&packet_data_eth) == 1)
		{
			packet_num++;
			packet_handler_eth(packet_header_eth, packet_data_eth);
			if (packet_num_eth_read < packet_num_eth_write && eth_wait)
			{
				wifi_cv.notify_one();
			}
		}		

		if (total_size == packet_num-1) 
		{
			break;
		}
	}
}

void wifi_thread_handle() 
{
	mutex mx;
	printf("WiFi thread created\n");
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
		u_long seq_num;

		//printf("WiFi handle \n");

		{
			/*struct pcap_pkthdr* packet_header;
			pcap_t* device_handle_i;
			char error_buffer[PCAP_ERRBUF_SIZE];

			if ((device_handle_i = pcap_open_offline("udp.pcap",	// File name 
				error_buffer					// Error buffer
				)) == NULL)
			{
				printf("\n Unable to open the file %s.\n", "udp.pcap");
				return;
			}

			pcap_next_ex(device_handle_i, &packet_header, (const u_char**)&packet_wifi);	*/	
		}

		/*udp_d = new ex_udp_datagram(packet_wifi);

		udp_d->iph->length = htons(4 + 20 + sizeof(udp_header));
		udp_d->uh->datagram_length = htons(sizeof(udp_header) + 4);*/
		*(rec_wifi_udp_d->seq_number) = *(packet_buffer_wifi[packet_num_wifi_read]->seq_number);
		/*udp_d->uh->dest_port = packet_buffer_wifi[packet_num_wifi_read]->uh->src_port;
		udp_d->uh->src_port = packet_buffer_wifi[packet_num_wifi_read]->uh->dest_port;*/

		//udp_d->iph->ttl = htons(100);


		/*for (j = 0; j < 6; j++)
		{
			udp_d->eh->dest_address[j] = packet_buffer_wifi[packet_num_wifi_read]->eh->src_address[j];
			udp_d->eh->src_address[j] = packet_buffer_wifi[packet_num_wifi_read]->eh->dest_address[j];
		}

		for (j = 0; j < 4; j++)
		{
			udp_d->iph->dst_addr[j] = packet_buffer_wifi[packet_num_wifi_read]->iph->src_addr[j];
			udp_d->iph->src_addr[j] = packet_buffer_wifi[packet_num_wifi_read]->iph->dst_addr[j];
		}*/

		seq_num = (u_long)ntohl(*(udp_d->seq_number));

		printf("Send ack from WiFi= %lu \n", seq_num);

		if (pcap_sendpacket(device_handle_in_wifi, ack_packet_wifi, 4 + sizeof(ethernet_header) + 20 + sizeof(udp_header)) == -1)
		{
			printf("Warning: The packet will not be sent.\n");
		}

		if (seq_num != 0)
		{
			packet_num_wifi_read++;
		}		//printf("WiFi handle end\n");
	}
}
// Callback function invoked by libpcap/WinPcap for every incoming packet form WiFi
void packet_handler_wifi(struct pcap_pkthdr* packet_header, unsigned char* packet_data)
{
	ex_udp_datagram* rec_packet;
	rec_packet = new ex_udp_datagram(packet_header, packet_data);

	u_long seq_num = (u_long)ntohl(*((u_long*)rec_packet->seq_number));

	if (seq_num == 0)
	{
		//total_size = ntohl(*(rec_packet->data));
		unsigned int* gepek = (unsigned int*)(rec_packet->data);
		total_size = ntohl(*gepek);
		printf("Total size :\n",total_size);
		message = new unsigned char[total_size * 10 + 1];

		*(rec_wifi_udp_d->seq_number) = *(rec_packet->seq_number);

		if (pcap_sendpacket(device_handle_in_wifi, ack_packet_wifi, 4 + sizeof(ethernet_header) + 20 + sizeof(udp_header)) == -1)
		{
			printf("Warning: The packet will not be sent.\n");
		}
	}
	else
	{
		packet_buffer_wifi[packet_num_wifi_write] = rec_packet;
		for (int i = 0; i < 10; i++)
		{
			printf("\nWIFIPACKET: %c\n", packet_buffer_wifi[packet_num_wifi_write]->data[i]);
		}
		packet_num_wifi_write++;
		printf("WiFi packet num recived = %d \n", packet_num_wifi_write);
	}
	packet_num++;
}

void eth_thread_handle()
{
	mutex mx;
	printf("Eth thread created\n");
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
		u_long seq_num;

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

		seq_num = (u_long)ntohl(*((u_long*)udp_d->seq_number));

		printf("Send ack from Eth= %lu \n", seq_num);

		if (pcap_sendpacket(device_handle_in_eth, packet_eth, 4 + sizeof(ethernet_header) + 20 + sizeof(udp_header)) == -1)
		{
			printf("Warning: The packet will not be sent.\n");
		}

		if (seq_num != 0)
		{
			packet_num_eth_read++;
		}
		//printf("Eth handle end \n");
	}
}

// Callback function invoked by libpcap/WinPcap for every incoming packet form Eth
void packet_handler_eth(struct pcap_pkthdr* packet_header,unsigned char* packet_data)
{
	ex_udp_datagram* rec_packet;
	rec_packet = new ex_udp_datagram(packet_header,packet_data);
	
	u_long seq_num = (u_long)ntohl(*((u_long*)rec_packet->seq_number));

	if (seq_num == 0)
	{
		total_size = ntohl((unsigned int)*(rec_packet->seq_number + 4));
		printf("Total size :\n",total_size);
		message = new unsigned char[total_size * 10 + 1];
	} 
	else
	{
		packet_buffer_eth[packet_num_eth_write] = rec_packet;
		for (int i = 0; i < 10; i++)
		{
			printf("\nETHPACKET: %c\n", packet_buffer_eth[packet_num_eth_write]->data[i]);
		}
		packet_num_eth_write++;
		printf("Eth packet num recived= %d \n", packet_num_eth_write);
	}	
	packet_num++;
}

void sort_packets(ex_udp_datagram* packet_buffer[],int buff_len) 
{
	int i,j;
	u_long key,cmp;

	for (i = 1; i < buff_len; i++) 
	{
		{
			u_long key = (u_long)ntohl((*(packet_buffer[i]->seq_number)));
		}
		j = i - 1;
		{
			if (j != 0)
			{
				u_long cmp = (u_long)ntohl((*(packet_buffer[j]->seq_number)));
			}
			else 
			{
				u_long cmp = -1;
			}
		}
		while (j >= 0 && cmp > key) 
		{
			packet_buffer[j + 1] = packet_buffer[j];
			j--;
		}
		packet_buffer[j + 1] = packet_buffer[i];
	}
}

void reconstruct_message() 
{
	sort_packets(packet_buffer_wifi,packet_num_wifi_write);
	sort_packets(packet_buffer_eth,packet_num_eth_write);
	merge_packets();

	int i,j,data_len,message_ind = 0;
	unsigned char* data;
	for (i = 0; i < total_size; i++) 
	{
		data = (unsigned char*)packet_buffer[i]->data;
		data_len = sizeof(data);
		for (j = 0; j < data_len; j++,data++,message_ind++) 
		{
			message[message_ind] = (unsigned char)ntohs(*data);
		}
	}
	message[message_ind] = '\0';
}

void merge_packets() 
{
	int i = 0, j = 0, k = 0;

	while (i < packet_num_wifi_write && j < packet_num_eth_write) 
	{
		u_long eth_seq = (u_long)ntohl((*(packet_buffer_eth[j]->seq_number))), wifi_seq = (u_long)ntohl((*(packet_buffer_wifi[i]->seq_number)));
		if (eth_seq > wifi_seq)
		{
			packet_buffer[k] = packet_buffer_wifi[i];
			i++;
		} 
		else 
		{
			packet_buffer[k] = packet_buffer_eth[j];
			j++;
		}
		k++;
	}
	
	while (i < packet_num_wifi_write) 
	{
		packet_buffer[k] = packet_buffer_wifi[i];
		i++;
		k++;
	}

	while (j < packet_num_eth_write)
	{
		packet_buffer[k] = packet_buffer_eth[j];
		j++;
		k++;
	}
}

