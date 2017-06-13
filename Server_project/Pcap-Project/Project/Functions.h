#pragma once
#include <thread>
#include <condition_variable>
#include <mutex>
#include <pcap.h>
#include "protocol_headers.h"

/* Reads generic udp packet from wireshark file. */
void initiallize(struct pcap_pkthdr** packet_header, unsigned char** packet_data)
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

void make_ack_packet(unsigned char **packet, unsigned char *udp_packet_data, struct pcap_pkthdr *udp_packet_header, unsigned short port_number)
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