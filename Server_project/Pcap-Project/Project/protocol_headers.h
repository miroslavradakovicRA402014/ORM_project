/* PROTOCOL HEADERS */
#define BUFF_LEN 10
// Ethernet header

typedef struct ethernet_header{
	unsigned char dest_address[6];		// Destination address
	unsigned char src_address[6];		// Source address
	unsigned short type;				// Type of the next layer
}ethernet_header;

// IPv4 header
typedef struct ip_header{
	unsigned char header_length :4;	// Internet header length (4 bits)
	unsigned char version :4;		// Version (4 bits)
	unsigned char tos;				// Type of service 
	unsigned short length;			// Total length 
	unsigned short identification;	// Identification 
	unsigned short fragm_flags :3;  // Flags (3 bits) & Fragment offset (13 bits)
    unsigned short fragm_offset :13;// Flags (3 bits) & Fragment offset (13 bits)
	unsigned char ttl;				// Time to live
	unsigned char next_protocol;	// Protocol of the next layer
	unsigned short checksum;		// Header checksum
	unsigned char src_addr[4];		// Source address
	unsigned char dst_addr[4];		// Destination address
	unsigned int options_padding;	// Option + Padding
		// + variable part of the header
}ip_header;

//UDP header
typedef struct udp_header{
	unsigned short src_port;		// Source port
	unsigned short dest_port;		// Destination port
	unsigned short datagram_length;	// Length of datagram including UDP header and data
	unsigned short checksum;		// Header checksum
}udp_header;

// TCP header
typedef struct tcp_header {
	unsigned short src_port;			// Source port
	unsigned short dest_port;			// Destination port
	unsigned int sequence_num;			// Sequence Number
	unsigned int ack_num;				// Acknowledgement number
	unsigned char reserved :4;			// Reserved for future use (4 bits) 
	unsigned char header_length :4;		// Header length (4 bits)
	unsigned char flags;				// Packet flags
	unsigned short windows_size;		// Window size
	unsigned short checksum;			// Header Checksum
	unsigned short urgent_pointer;		// Urgent pointer
	// + variable part of the header
} tcp_header;

typedef struct ex_udp_datagram
{
	ethernet_header *eh;
	ip_header *iph;
	udp_header *uh;
	u_long *seq_number;
	unsigned char* data;


	ex_udp_datagram(struct pcap_pkthdr *packet_header, unsigned char *packet_data)
	{
		eh = (ethernet_header*)packet_data;
		iph = (ip_header*)(packet_data + sizeof(ethernet_header));

		int tmp = iph->header_length * 4;

		uh = (udp_header*)((unsigned char*)iph + tmp);

		seq_number = (u_long *)((unsigned char*)uh +sizeof(udp_header));
		data = (unsigned char *)((unsigned char*)uh+sizeof(udp_header)+sizeof(u_long));
	}

	ex_udp_datagram(unsigned char *packet_data)
	{
		eh = (ethernet_header*)packet_data;
		iph = (ip_header*)(packet_data + sizeof(ethernet_header));

		int tmp = iph->header_length * 4;

		uh = (udp_header*)((unsigned char*)iph + tmp);

		seq_number = (u_long *)((unsigned char*)uh +sizeof(udp_header));
	}
} ex_udp_datagram;