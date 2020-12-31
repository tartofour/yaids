#include <stdio.h>
#include "populate.h"

void generate_ip(unsigned int ip, char ip_addr[])
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    snprintf(ip_addr,IP_ADDR_LEN_STR,
        "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]); 
}

void print_payload(int payload_length, unsigned char *payload)
{
	if (payload_length > 0) 
    {
        const u_char *temp_pointer = payload;
        int byte_count = 0;
        while (byte_count++ < payload_length) 
        {
            printf("%c", (char)*temp_pointer);
            temp_pointer++;
        }
        printf("\n");
    }
}

void print_ethernet_header(ETHER_Frame *frame)
{
    printf("Source MAC : %s\n", frame->source_mac);
	printf("Destination MAC : %s\n", frame->source_mac);
    printf("Ethertype : %d\n", frame->ethertype);
    printf("\n");
}

void print_ip_header(IP_Packet *packet)
{
    printf("Source IP : %s\n", packet->source_ip);
	printf("Destination IP : %s\n", packet->destination_ip);
    printf("Layer 4 protocol : %d\n", packet->protocol);
    printf("\n");
}

void print_tcp_header(TCP_Segment *segment)
{
    printf("Source Port : %d\n", segment->source_port);
	printf("Destination Port : %d\n", segment->destination_port);
	printf("Sequence Number : %d\n", segment->sequence_number);
	printf("ACK number : %d\n", segment->ack_number);
	printf("Flag : %d\n", segment->flag);
    printf("Data Length : %d\n", segment->data_length);
    printf("\n");
}

void print_udp_header(UDP_Datagram *datagram)
{
    printf("Source Port : %d\n", datagram->source_port);
	printf("Destination Port : %d\n", datagram->destination_port);
    printf("Data Length : %d\n", datagram->data_length);
    printf("\n");
}

void print_icmp_header(ICMP_Msg *message)
{
    printf("Type : %d\n", message->type);
    printf("Code : %d\n", message->code);
	printf("ID : %d\n", message->id);
	printf("Sequence : %d\n", message->sequence);
	printf("\n");
}	

int populate_packet_ds(const struct pcap_pkthdr *header, const u_char *packet, ETHER_Frame *custom_frame)
{
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	//const struct sniff_arp *arp; /* The IP header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_icmp *icmp; /*The ICMP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const struct sniff_udp *udp; /*The UDP header */
	unsigned char *payload = NULL; /* Packet payload */

	u_int size_ip;
	u_int size_tcp;
	u_int size_udp;
	
	ethernet = (struct sniff_ethernet*)(packet);
	char src_mac_address[ETHER_ADDR_LEN_STR];
	char dst_mac_address[ETHER_ADDR_LEN_STR];

	// Convert unsigned char MAC to string MAC
	for(int x=0;x<6;x++)
	{       
		snprintf(src_mac_address+(x*2),ETHER_ADDR_LEN_STR, "%02x", ethernet->ether_shost[x]);
		snprintf(dst_mac_address+(x*2),ETHER_ADDR_LEN_STR, "%02x", ethernet->ether_dhost[x]);
	}

	strcpy(custom_frame->source_mac,src_mac_address);
	strcpy(custom_frame->destination_mac, dst_mac_address);
	custom_frame->frame_size = header->caplen;
	custom_frame->ethertype = ethernet->ether_type;
	//print_ethernet_header(custom_frame);
	
	if(ntohs(ethernet->ether_type) == ETHERTYPE_ARP) 
	{
		custom_frame->ethertype = ARP;
		//arp = (struct sniff_arp*)(packet + SIZE_ETHERNET);
		//ARP_Packet custom_arp_packet;
		strcpy(custom_frame->payload_protocol, "arp");
		//print_ethernet_header(ethernet);
	}
		
	if(ntohs(ethernet->ether_type) == ETHERTYPE_IP) 
	{
		custom_frame->ethertype = IPV4;
		IP_Packet custom_packet;
		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	   
		char src_ip[IP_ADDR_LEN_STR];
		char dst_ip[IP_ADDR_LEN_STR];
		generate_ip(ip->ip_src.s_addr,src_ip);
		generate_ip(ip->ip_dst.s_addr,dst_ip);

		strcpy(custom_packet.source_ip,src_ip);
		strcpy(custom_packet.destination_ip, dst_ip);
		custom_packet.protocol = ip->ip_p; 
		//print_ip_header(&custom_packet);

		size_ip = IP_HL(ip)*4;

		if (size_ip < 20) 
		{
			printf("   * Invalid IP header length: %u bytes\n", size_ip);
			return ERROR;
		}
		
		if((int)ip->ip_p==ICMP_PROTOCOL)
		{
			ICMP_Msg custom_icmp_msg;
			icmp = (struct sniff_icmp*)(packet + SIZE_ETHERNET + size_ip);
			
			custom_icmp_msg.type = ntohs(icmp->icmp_type);
			custom_icmp_msg.code = ntohs(icmp->icmp_code);
			custom_icmp_msg.id = ntohs(icmp->icmp_id);
			custom_icmp_msg.sequence = ntohs(icmp->icmp_sequence);
			
			custom_packet.icmp_data = custom_icmp_msg;
			custom_frame->ip_data = custom_packet;
			strcpy(custom_frame->payload_protocol, "icmp");
			//print_icmp_header(&custom_icmp_msg);
		}
		
		if((int)ip->ip_p==UDP_PROTOCOL)
		{
			UDP_Datagram custom_udp_packet;				
			udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);	
			size_udp = (int)udp->uh_ulen;
			
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
			
			custom_udp_packet.source_port = ntohs(udp->uh_sport);
			custom_udp_packet.destination_port = ntohs(udp->uh_dport);
			custom_udp_packet.data = payload;
			custom_udp_packet.data_length = udp->uh_ulen;
			strcpy(custom_frame->payload_protocol, "udp");
						
			custom_packet.udp_data = custom_udp_packet;
			custom_frame->ip_data = custom_packet;
			//print_udp_header(&custom_udp_packet);
		}
		
		if((int)ip->ip_p==TCP_PROTOCOL)
		{
			TCP_Segment custom_segment;
			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = TH_OFF(tcp)*4;

			if (size_tcp < 20) {
					printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
					return ERROR;
			}
			
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

			int payload_length = (header->len)-SIZE_ETHERNET-size_ip-size_tcp;
			
			custom_segment.source_port = ntohs(tcp->th_sport);
			custom_segment.destination_port = ntohs(tcp->th_dport);
			custom_segment.flag = (int)tcp->th_flags;
			custom_segment.sequence_number = tcp->th_seq;
			custom_segment.data = payload;
			custom_segment.data_length = payload_length;

			custom_packet.tcp_data = custom_segment;
			custom_frame->ip_data = custom_packet;
			strcpy(custom_frame->payload_protocol, "tcp");
			
			//print_tcp_header(&custom_segment);
		  	
			if(custom_frame->ip_data.tcp_data.source_port == 443 || custom_frame->ip_data.tcp_data.destination_port == 443)
			{
		 		strcpy(custom_frame->payload_protocol, "https");
			}
		  	if(strstr((char*)custom_segment.data, "HTTP/1.1") != NULL || strstr((char*)custom_segment.data, "HTTP/1.2") != NULL || strstr((char*)custom_segment.data, "HTTP/2") != NULL)
			{
				strcpy(custom_frame->payload_protocol, "http");
			}
			if(strstr((char*)custom_segment.data, "SSH-2.0-OpenSSH") != NULL)
			{
				strcpy(custom_frame->payload_protocol, "ssh");
			}
			if(strstr((char*)custom_segment.data, "220 (vsFTPd ") != NULL)
			{
				strcpy(custom_frame->payload_protocol, "ftp");
			}
		}
	}
	return 0;
}

