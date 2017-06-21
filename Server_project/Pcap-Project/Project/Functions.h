#pragma once
#include <thread>
#include <condition_variable>
#include <mutex>
#include <pcap.h>
#include "protocol_headers.h"

/* Reads generic udp packet from wireshark file. */
void initialize(struct pcap_pkthdr** packet_header, unsigned char** packet_data)
{
	pcap_t* device_handle_i;
	char error_buffer[PCAP_ERRBUF_SIZE];

	if ((device_handle_i = pcap_open_offline("udp.pcap",	// File name 
		error_buffer					// Error buffer
	)) == NULL)
	{
		printf("\n Unable to open the file %s.\n", "udp.pcap");
		return;
	}


	pcap_next_ex(device_handle_i, packet_header, (const u_char**)packet_data);
}

void make_ack_packet(unsigned char **packet, unsigned char *udp_packet_data, struct pcap_pkthdr *udp_packet_header, const unsigned short port_number)
{
	/* Help structures. */
	ex_udp_datagram *udp_d = new ex_udp_datagram(udp_packet_header, udp_packet_data);
	ip_header *iph;
	udp_header *uh;

	unsigned int header_size = sizeof(ethernet_header) + udp_d->iph->header_length * 4 + sizeof(udp_header) + 4; //4 bytes for ACK num
																								
	*packet = new unsigned char[header_size];
	/* Copy header from generic packet. */
	memcpy(*packet, udp_packet_data, header_size);

	/* Setting header fields which indicates packet size. */
	iph = (ip_header*)(*packet + sizeof(ethernet_header));
	uh = (udp_header*)(*packet + iph->header_length * 4 + sizeof(ethernet_header));
	iph->length = htons(header_size - sizeof(ethernet_header));
	uh->datagram_length = htons(header_size - iph->header_length * 4 - sizeof(ethernet_header));
	uh->src_port = htons(port_number);
	uh->dest_port = htons(port_number);

	delete udp_d;
}

void set_addresses(unsigned char **packets, unsigned int packets_num, unsigned char eth_src_addr[], unsigned char eth_dst_addr[], unsigned char ip_src_addr[], unsigned char ip_dst_addr[])
{
	ip_header *iph;
	ethernet_header *eh;
	for (int i = 0; i < packets_num; i++)
	{
		eh = (ethernet_header*)packets[i];
		iph = (ip_header*)(packets[i] + sizeof(ethernet_header));
		for (int i = 0; i < 6; i++)
		{
			eh->dest_address[i] = eth_dst_addr[i];
			eh->src_address[i] = eth_src_addr[i];
		}

		for (int i = 0; i < 4; i++)
		{
			iph->dst_addr[i] = ip_dst_addr[i];
			iph->src_addr[i] = ip_src_addr[i];
		}
	}
}

using namespace std;

char* convert_sockaddr_to_string(struct sockaddr* address)
{
	return (char *)inet_ntoa(((struct sockaddr_in *) address)->sin_addr);
}

char *get_interface_addr(pcap_if_t *dev)
{
	pcap_addr_t *addr;

	// IP addresses
	for (addr = dev->addresses; addr; addr = addr->next)
	{
		if (addr->addr->sa_family == AF_INET)
		{
			if (addr->addr != NULL)
			{
				return convert_sockaddr_to_string(addr->addr);
			}
		}
	}
}

void get_addresses(pcap_if_t *device, unsigned char ip_addr[][4], unsigned char eth_addr[][6], int id)
{
	char input[19];
	unsigned int eth_tmp[6];
	if (id == 0)
	{
		printf("Enter WiFi mac address (format : xx:xx:xx:xx:xx:xx) : \n");
		scanf("%s", input);
	}
	else
	{
		printf("Enter ethernet mac address (format : xx:xx:xx:xx:xx:xx) : \n");
		scanf("%s", input);
	}

	printf("%s\n", input);

	sscanf(input, "%02x:%02x:%02x:%02x:%02x:%02x", &eth_tmp[0], &eth_tmp[1], &eth_tmp[2], &eth_tmp[3],
		&eth_tmp[4], &eth_tmp[5]);

	for (int i = 0; i < 6; i++)
		eth_addr[id][i] = (unsigned char)eth_tmp[i];

	/*for (int i = 0; i < 6; i++)
	printf("%hhu ", eth_addr[id][i]);*/

	char *ip_addr_str = get_interface_addr(device);
	sscanf(ip_addr_str, "%hhu.%hhu.%hhu.%hhu", &ip_addr[id][0], &ip_addr[id][1], &ip_addr[id][2], &ip_addr[id][3]);

	/*printf("wifi\n");
	for (int i = 0; i < 4; i++)
	printf("%u ", ip_addr[0][i]);
	printf("eth\n");
	for (int i = 0; i < 4; i++)
	printf("%u ", ip_addr[1][i]);*/
}

void set_filter_exp(char **filter_exp, pcap_if_t *device, unsigned int portNumber)
{
	char portNumStr[] = "00000";
	sprintf(portNumStr, "%u", portNumber);
	string filter_exp_tmp("udp dst port ");

	filter_exp_tmp += string(portNumStr);
	filter_exp_tmp += " and ip dst ";
	filter_exp_tmp += string(get_interface_addr(device));

	*filter_exp = new char[filter_exp_tmp.size()];
	strcpy(*filter_exp, filter_exp_tmp.data());

	//printf("%s\n", *filter_exp);
}


//! \brief Calculate the IP header checksum.
//! \param buf The IP header content.
//! \param hdr_len The IP header length.
//! \return The result of the checksum.
uint16_t ip_checksum(const void *buf, size_t hdr_len)
{
	unsigned long sum = 0;
	const uint16_t *ip1;

	ip1 = (const uint16_t *)buf;
	while (hdr_len > 1)
	{
		sum += *ip1++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		hdr_len -= 2;
	}

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return(~sum);
}
//! \brief Calculate the UDP header checksum.
//! \param buf The UDP header content.
//! \param hdr_len The UDP header length.
//! \return The result of the checksum.
uint16_t udp_checksum(const void *buff, size_t hdr_len, unsigned char* src_addr, unsigned char* dest_addr)
{
	const uint16_t *buf = (const uint16_t *)buff;
    uint16_t *ip_src = (uint16_t *)src_addr, *ip_dst = (uint16_t *)dest_addr;
    uint32_t sum;
    size_t length = hdr_len;
                                         
    sum = 0;
    while (hdr_len > 1)
    {
        sum += *buf++;
           if (sum & 0x80000000)
              sum = (sum & 0xFFFF) + (sum >> 16);
        hdr_len -= 2;
   }
   if (hdr_len & 1)
      sum += *((uint8_t *)buf);                                      
   sum += *ip_src;
   sum += *(ip_dst++);
   sum += *ip_dst;

   sum += htons(IPPROTO_UDP);
   sum += htons(length);

   while (sum >> 16)
       sum = (sum & 0xFFFF) + (sum >> 16);
   return ((uint16_t)(~sum));
}
