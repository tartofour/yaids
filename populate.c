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

int populate_packet_ds(const struct pcap_pkthdr *header, const u_char *packet, ETHER_Frame *custom_frame)
{
			
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_icmp *icmp; /*The ICMP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const struct sniff_udp *udp; /*The UDP header */
	unsigned char *payload; /* Packet payload */

	u_int size_ip;
	u_int size_icmp;
	u_int size_tcp;
	u_int size_udp;
	u_int size_payload;

	ethernet = (struct sniff_ethernet*)(packet);
	char src_mac_address[ETHER_ADDR_LEN_STR];
	char dst_mac_address[ETHER_ADDR_LEN_STR];

	// Convert unsigned char MAC to string MAC
	for(int x=0;x<6;x++)
	{       snprintf(src_mac_address+(x*2),ETHER_ADDR_LEN_STR,
					"%02x",ethernet->ether_shost[x]);
			snprintf(dst_mac_address+(x*2),ETHER_ADDR_LEN_STR,
					"%02x",ethernet->ether_dhost[x]);
	}

	strcpy(custom_frame->source_mac,src_mac_address);
	strcpy(custom_frame->destination_mac, dst_mac_address);
	custom_frame->frame_size = header->caplen;
	custom_frame->ethernet_type = ethernet->ether_type;
   /* 
	printf("\nEthernet Frame\n");
	printf("MAC Source : %s\n", custom_frame->source_mac);
	printf("MAC Destination : %s\n", custom_frame->destination_mac);
	printf("Frame size : %d\n", custom_frame->frame_size);
	printf("Ethertype : %d\n", custom_frame->ethernet_type);
	*/
	
	// ARP
	/*
	if(ntohs(ethernet->ether_type) == ETHERTYPE_ARP) 
	{
		custom_frame->ethernet_type = ARP;
		printf("\nARP packet: %d\n",custom_frame->ethernet_type);
		
		arp = (struct sniff_ip*)(packet + SIZE_ETHERNET);
		ARP_Packet custom_packet;    
	}
	*/
		
		
		//IP
	if(ntohs(ethernet->ether_type) == ETHERTYPE_IP) 
	{
		custom_frame->ethernet_type = IPV4;
		printf("\nIPV4 packet: %d\n",custom_frame->ethernet_type);

		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
		IP_Packet custom_packet;
	   
		char src_ip[IP_ADDR_LEN_STR];
		char dst_ip[IP_ADDR_LEN_STR];
		int protocole;
		generate_ip(ip->ip_src.s_addr,src_ip);
		generate_ip(ip->ip_dst.s_addr,dst_ip);

		strcpy(custom_packet.source_ip,src_ip);
		strcpy(custom_packet.destination_ip, dst_ip);
		custom_packet.protocole = ip->ip_p; 

		size_ip = IP_HL(ip)*4;

		if (size_ip < 20) 
		{
			printf("   * Invalid IP header length: %u bytes\n", size_ip);
			return ERROR;
		}
		
		/*
		printf("\nIP Packet\n");
		printf("IP Source : %s\n", custom_packet.source_ip);
		printf("IP Destination : %s\n", custom_packet.destination_ip);
		printf("Protocole couche 4 : %d\n", custom_packet.protocole);
		*/
		if((int)ip->ip_p==ICMP_PROTOCOL)
		{
			printf("\nICMP Handling\n");
			icmp = (struct sniff_icmp*)(packet + SIZE_ETHERNET + size_ip);
			ICMP_Msg custom_icmp_msg;
			
			//size_icmp = 
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_icmp);
			int payload_length = (header->caplen)-SIZE_ETHERNET-size_ip-size_icmp;
			
			custom_icmp_msg.type = ntohs(icmp->icmp_type);
			custom_icmp_msg.code = ntohs(icmp->icmp_code);
			custom_icmp_msg.id = ntohs(icmp->icmp_id);
			custom_icmp_msg.sequence = ntohs(icmp->icmp_sequence);
			
			custom_packet.icmp_data = custom_icmp_msg;
			custom_frame->ip_data = custom_packet;
			
			/*
			printf("\nICMP Message\n");
			printf("Type : %d\n", custom_icmp_msg.type);
			printf("Code : %d\n", custom_icmp_msg.code);
			printf("ID : %d\n", custom_icmp_msg.id);
			printf("Sequence : %d\n", custom_icmp_msg.sequence);					
			*/
			//print_payload(payload_length, payload);
		}
		
		
		if((int)ip->ip_p==UDP_PROTOCOL)
		{
			printf("\nUDP Handling\n");
			udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);	
			UDP_Datagram custom_udp_packet;				
			
			size_udp = (int)udp->uh_ulen;
			
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
			int payload_length = (header->caplen)-SIZE_ETHERNET-size_ip-size_udp;
			
			custom_udp_packet.source_port = ntohs(udp->uh_sport);
			custom_udp_packet.destination_port = ntohs(udp->uh_dport);
			custom_udp_packet.data = payload;
			custom_udp_packet.data_length = udp->uh_ulen;
			/*
			printf("\nUDP Datagram\n");
			printf("Port Source : %d\n", custom_udp_packet.source_port);
			printf("Port Destination : %d\n", custom_udp_packet.destination_port);
			printf("Longueur Data : %d\n", custom_udp_packet.data_length);
			//print_payload(custom_udp_packet.data_length, custom_udp_packet.data);
			*/
			custom_packet.udp_data = custom_udp_packet;
			custom_frame->ip_data = custom_packet;
	 
		}
		
		if((int)ip->ip_p==TCP_PROTOCOL)
		{
			printf("\nTCP Handling\n");
			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
			TCP_Segment custom_segment;

			size_tcp = TH_OFF(tcp)*4;

			if (size_tcp < 20) {
					printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
					return ERROR;
			}
			
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

			int payload_length = (header->len)-SIZE_ETHERNET-size_ip-size_tcp;
			
			custom_segment.source_port = ntohs(tcp->th_sport);
			custom_segment.destination_port = ntohs(tcp->th_dport);
			custom_segment.th_flag = (int)tcp->th_flags;
			custom_segment.sequence_number = tcp->th_seq;
			custom_segment.data = payload;
			custom_segment.data_length = payload_length;
			
			custom_packet.tcp_data = custom_segment;
			custom_frame->ip_data = custom_packet;
		  
			/*
			printf("Tailles\n");
			printf("taille header : %d\n", header->caplen);
			printf("taille ethernet : %d\n", SIZE_ETHERNET);
			printf("taille ip : %d\n", size_ip);
			printf("taille tcp : %d\n", size_tcp);
			printf("Payload length : %d\n", payload_length);

			
			printf("\nTCP Segment\n");
			printf("Port Source : %d\n", custom_segment.source_port);
			printf("Port Destination : %d\n", custom_segment.destination_port);
			printf("Flag : %d\n", custom_segment.th_flag);
			printf("Sequence number : %d\n", custom_segment.sequence_number);
			printf("Payload length : %d\n", custom_segment.data_length);
			*/
				
		}
	}
	return 0;
}

