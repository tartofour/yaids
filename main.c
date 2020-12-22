/* TODO : 

 * 	- TCP SYN attack
 * 		
 * 		- creer un tableau de structure syn_requests qui contient l'ip src, 
 * 		  l'ip dest, et timestamp
 * 			- ajouter tout les packet tcp qui arrivnet (.
 * 		- realloc le tableau à chaque paquet TCP syn qui entre
 * 		- define un threshold
 * 
 * 	- ARP spoofing
 * 		- tableau arp_request
 * 
 * 	- Comment détecter si payload chiffré ?
 * 
 * 	- XSS detector / injection SQL
 * 		⁻ regex pcre ?
 * 
 
 * 
 * 	- DHCP
 * 	- DNS

 * 	- SMB
 * 	- TLS
 * 	- RDP
 * 	- SNMP
 * 	- telnet
 * 				
 * 
 */	



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <errno.h>
#include <stdbool.h>
#include <syslog.h>
//#include <time.h>
//#include <zlib.h>
#include "populate.h"

#define ACTION_LEN_STR 14
#define PROTOCOL_LEN_STR 15
#define IP_ADDR_LEN_STR 16
#define DIRECTION_LEN_STR 3

#define HTTP_VERSION_LEN 20
#define HTTP_STATUS_LEN 20
#define HTTP_METHOD_LEN 10
#define HTTP_MSG_TYPE_LEN 9
#define HTTP_HOST_LEN 255
#define HTTP_CONTENT_TYPE_LEN 255
#define HTTP_ENCODING_LEN 50

#define STR_MAX_SIZE 255
#define ARGS_MAX_SIZE 255

struct ids_rule
{
    char action[ACTION_LEN_STR];
    char protocol[PROTOCOL_LEN_STR];
    char ip_src[IP_ADDR_LEN_STR];
    int port_src;
    char direction[DIRECTION_LEN_STR];
    char ip_dst[IP_ADDR_LEN_STR];
    int port_dst;
    char content[STR_MAX_SIZE];
    char msg[STR_MAX_SIZE];
   // int count;
   // time_t seconds;
    
} typedef Rule;

struct http_message
{
	char version[HTTP_VERSION_LEN];
	int status; 
	char method[HTTP_METHOD_LEN]; // POST, GET		
	char msg_type[HTTP_MSG_TYPE_LEN];
	char host[HTTP_HOST_LEN];
	char content_type[HTTP_CONTENT_TYPE_LEN];
	char encoding[HTTP_ENCODING_LEN]; // gzip - deflate - ...
	int body_len;
	unsigned char *body;
	
} typedef Http_msg;

struct pcap_arguments
{
	int rules_counter;
	Rule *rules_ptr;
	
} typedef Pcap_args;

/*
int check_syn_flood(struct packet_syn, ETHER_Frame *frame, time_t capture_time)
{
	
}

*/

/*
int gzip_inflate(char *compr, int comprLen, char *uncompr, int uncomprLen)
{
    int err;
    z_stream d_stream; // decompression stream 

    d_stream.zalloc = (alloc_func)0;
    d_stream.zfree = (free_func)0;
    d_stream.opaque = (voidpf)0;

    d_stream.next_in  = (unsigned char *)compr;
    d_stream.avail_in = comprLen;

    d_stream.next_out = (unsigned char *)uncompr;
    d_stream.avail_out = uncomprLen;

    err = inflateInit2(&d_stream, 16+MAX_WBITS);
    if (err != Z_OK) return err;

    while (err != Z_STREAM_END) err = inflate(&d_stream, Z_NO_FLUSH);

    err = inflateEnd(&d_stream);
    return err;
}
*/

void print_help(char * prg_name)
{
    printf("Utilisation : ");
    printf("%s rules_file [interface]\n", prg_name);
    printf("Écoute le traffic sur une interface réseau et ajoute une entrée dans syslog lors de la détection d'une activité dont la signature correspond avec une ou plusieurs règles définies dans le ficher rules_file.\n");
    printf("\t-h,           affiche ce message\n");
}

void print_error(char * err_str)
{
    fprintf(stderr, "Erreur : %s\n", err_str);
    fprintf(stderr, "Pour le menu d'aide utilisez l'option -h\n");
}

void print_rules(Rule *rules, int count)
{
    int i;
    
    for (i=0; i<count; i++)
    {
        printf("Rules n°%d\n", i);
		printf("Action : %s\n", rules[i].action);
		printf("Protocol : %s\n", rules[i].protocol);
		printf("Source IP : %s\n", rules[i].ip_src);
		printf("Source Port : %d\n", rules[i].port_src);
		printf("Direction : %s\n", rules[i].direction);
		printf("Destination IP : %s\n", rules[i].ip_dst);
		printf("Destination Port : %d\n", rules[i].port_dst);
		if (strlen(rules[i].msg) > 0)
		{
			printf("Msg : %s\n", rules[i].msg);
		}
		if (strlen(rules[i].content) > 0)
		{
			printf("Content : %s\n", rules[i].content);
		}		
		printf("\n");
    }
}

void initialize_http_message_struct(Http_msg message)
{
	memset(message.version, 0, HTTP_VERSION_LEN);
	memset(message.method, 0, HTTP_METHOD_LEN);
	memset(message.msg_type, 0, HTTP_MSG_TYPE_LEN);
	memset(message.host, 0, HTTP_HOST_LEN);
	memset(message.content_type, 0, HTTP_CONTENT_TYPE_LEN);
	memset(message.encoding, 0, HTTP_ENCODING_LEN);
	message.status = -1;
	message.body_len = -1;
	message.body = NULL;
}

void initialize_rule_struct(Rule *rule)
{
	memset(rule->action, '\0', ACTION_LEN_STR);
	memset(rule->protocol, '\0', PROTOCOL_LEN_STR);
	memset(rule->ip_src, '\0', IP_ADDR_LEN_STR);
	memset(rule->direction, '\0', DIRECTION_LEN_STR);
	memset(rule->ip_dst, '\0', IP_ADDR_LEN_STR);
	memset(rule->content, '\0', STR_MAX_SIZE);
	memset(rule->msg, '\0', STR_MAX_SIZE);
	rule->port_src = -1;
	rule->port_dst = -1;
	//rule->count = -1;
	//rule->seconds = -1;
}

void remove_char_from_str(char *new_str, char *str, char char_to_remove)
{	
	int i = 0;
	int j = 0;
	
	while (str[i] != '\0')
	{
		if (str[i] != char_to_remove)
		{
			new_str[j] = str[i];
			j++;
		}		
		i++;
	}
	new_str[j] = '\0';
}

bool is_action_in_rules_valid(char *action_str)
{
    if(strcmp(action_str, "alert") == 0)
    {   
        return true;
    }   
    return false;
}

bool is_protocol_in_rules_valid(char *protocol)
{
	if(strcmp(protocol, "http") == 0 ||
		strcmp(protocol, "tcp") == 0 ||
		strcmp(protocol, "udp") == 0 ||
		strcmp(protocol, "icmp") == 0 ||
		strcmp(protocol, "ssh") == 0 ||
		strcmp(protocol, "ftp") == 0)
		
		return true;
		
	return false;
}

bool is_ip_in_rules_valid(char *ip)
{
	char ip_buffer[1000];
	
	char *ip_field;
	char *ip_field_error;
	char *ip_field_save_ptr;
	
	int byte;
	int byte_nb;
	
	if(strcmp(ip, "any") == 0)
	{
		return true;
	}
	
	strcpy(ip_buffer, ip);
	
	ip_field = strtok_r(ip_buffer, ".", &ip_field_save_ptr);
	byte_nb = 0;

	while (ip_field != NULL)
	{
		byte = strtol(ip_field, &ip_field_error, 10);

		if(byte < 0 || byte > 255 || *ip_field_error != '\0')
		{
			return false;
		}
		
		byte_nb++;
		ip_field = strtok_r(NULL, ".", &ip_field_save_ptr);
	}
	
	if(byte_nb != 4)
	{
		return false;
	}
	
	return true;	
}

bool is_port_in_rules_valid(char *port)
{	
	if (strcmp(port, "any") == 0 || (atoi(port) >= 1 && atoi(port) <= 65535))
	{
		return true;
	}  
	return false; 
}    

bool is_direction_in_rules_valid(char *direction)
{
	if(strcmp(direction, "->") == 0 || strcmp(direction, "<-") == 0)
	{
		return true;
	}	
	return false;
}

bool is_ip_match(char* rules_ip, char* captured_ip)
{
	if (strcmp(rules_ip, "any") == 0 || strcmp(rules_ip, captured_ip) == 0)
	{
		return true;
	}
	return false;
}

bool is_port_match(int rule_port, int capture_port)
{
	if (rule_port == 0 || rule_port == capture_port)
	{
		return true;
	}
	return false;
}

void check_interface_validity(char *choosen_interface_name)
{
    struct ifaddrs *ifa, *ifa_tmp;

    if (getifaddrs(&ifa) == -1)
    {
        print_error("aucun interface détecté sur la machine");
        exit(EXIT_FAILURE);
    }

    for (ifa_tmp = ifa; ifa_tmp; ifa_tmp = ifa_tmp->ifa_next)
    {
        if (strcmp(ifa_tmp->ifa_name,choosen_interface_name) == 0 && \
            ifa_tmp->ifa_addr->sa_family==AF_INET)
        {
            freeifaddrs(ifa);
            return;
        }
    }
    print_error("interface non trouvé sur la machine");
    exit(EXIT_FAILURE);
}

int check_args_validity(int argc, char * argv[])
{
    if (argc == 1)
    {
       print_help(argv[0]);
       exit(EXIT_SUCCESS);
    }

    if (strcmp(argv[1], "-h") == 0)
    {
       print_help(argv[0]);
       exit(EXIT_SUCCESS);
    }

    if (argc < 2 || argc > 3)
    {
        print_error("nombre d'arguments invalides");
        exit(EXIT_FAILURE);
    }
    
    if (argc == 2)
	{
		if (strlen(argv[1]+1) > ARGS_MAX_SIZE)
		{
			print_error("limite de caractères dépassée par l'argument");
			exit(EXIT_FAILURE);
		}
	}
    
	if (argc == 3)
	{
		if (strlen(argv[1]+1) > ARGS_MAX_SIZE || strlen(argv[2]+1) > ARGS_MAX_SIZE)
		{
			print_error("limite de caractères dépassée par un ou plusieurs arguments");
			exit(EXIT_FAILURE);
		}
		
	}

 
    return 0;
}

void assign_default_interface(char *device)
{
	pcap_if_t *interfaces;
	char error[PCAP_ERRBUF_SIZE];
	
	if(pcap_findalldevs(&interfaces,error)==-1)
    {
		print_error("Aucun interface détecté sur la machine");
        exit(EXIT_FAILURE);   
    }

    strcpy(device, interfaces->name);
}

void assign_interface(int argc, char *argv[], char *device)
{
	if (argc == 2)
	{
		assign_default_interface(device);
	}
    
	if (argc == 3)
	{
		check_interface_validity(argv[2]);
		strcpy(device, argv[2]);
	}	
}

int count_file_lines(FILE* file)
{
    int count_lines = 0;
    char character = getc(file);

    while (character != EOF)
    {
        if (character == '\n')
        {
            count_lines++;
        }
        character = getc(file);
    }
    rewind(file);
    return count_lines;
}

Rule* rules_malloc(int count)
{
    Rule* ptr = (Rule *) malloc(sizeof(Rule) * count);
    int i;
    
    for(i=0; i<count; i++)
    {
		memset(ptr->action, 0, ACTION_LEN_STR);
		memset(ptr->protocol, 0, PROTOCOL_LEN_STR);
		memset(ptr->ip_src, 0, IP_ADDR_LEN_STR);
		memset(ptr->direction, 0, DIRECTION_LEN_STR);
		memset(ptr->ip_dst, 0, IP_ADDR_LEN_STR);
		memset(ptr->content, 0, STR_MAX_SIZE);
		memset(ptr->msg, 0, STR_MAX_SIZE);
		ptr->port_src = -1;
		ptr->port_dst = -1;
	}
	
    return ptr;
}

int populate_rule_header(char *line, Rule *rule_ds)
{
	char *saveptr = NULL;
    char *action_ptr = NULL;
    char *protocol_ptr = NULL;
    char *ip_src_ptr = NULL;
    char *port_src_ptr = NULL;
    char *direction_ptr = NULL;
    char *ip_dst_ptr = NULL;
    char *port_dst_ptr = NULL;
    char *error_ptr = NULL;
    
    action_ptr = strtok_r(line, " ", &saveptr);
    protocol_ptr = strtok_r(NULL, " ", &saveptr);
    ip_src_ptr = strtok_r(NULL, " ", &saveptr);
    port_src_ptr = strtok_r(NULL, " ", &saveptr);
    direction_ptr = strtok_r(NULL, " ", &saveptr);
    ip_dst_ptr = strtok_r(NULL, " ", &saveptr);
    port_dst_ptr = strtok_r(NULL, " ", &saveptr);
    error_ptr = strtok_r(NULL, " ", &saveptr);

	if (error_ptr != NULL || action_ptr == NULL || protocol_ptr == NULL || ip_src_ptr == NULL || port_src_ptr == NULL || direction_ptr == NULL || ip_dst_ptr == NULL || port_dst_ptr == NULL)
	{
		return -1;
	}
	
	int action_valid = is_action_in_rules_valid(action_ptr);
	int protocol_valid = is_protocol_in_rules_valid(protocol_ptr);
	int direction_valid = is_direction_in_rules_valid(direction_ptr);
	int ip_addresses_valid = is_ip_in_rules_valid(ip_src_ptr) && is_ip_in_rules_valid(ip_dst_ptr);
	int ports_valid = is_port_in_rules_valid(port_src_ptr) && is_port_in_rules_valid(port_dst_ptr); 
	
	if (!action_valid || !protocol_valid || !direction_valid || !ip_addresses_valid || !ports_valid)
	{
		return -1;
	}

	strcpy(rule_ds->action, action_ptr);
	strcpy(rule_ds->protocol, protocol_ptr);
	strcpy(rule_ds->direction, direction_ptr);
	strcpy(rule_ds->ip_src, ip_src_ptr);
	strcpy(rule_ds->ip_dst, ip_dst_ptr);
	rule_ds->port_src = atoi(port_src_ptr);
	rule_ds->port_dst = atoi(port_dst_ptr);
		
     return 0;
}

int populate_rule_option(char *line, Rule *rule_ds)
{
	char option_buffer[1000];
	char value_buffer[1000];
	char *options_ptr = NULL;
	char *option_ptr = NULL;
    char *value_ptr = NULL;
    char *options_save_ptr = NULL;
    char *option_save_ptr = NULL;
    
	options_ptr = strtok_r(line, ";", &options_save_ptr);
	
	while(options_ptr != NULL)
	{
		option_ptr = strtok_r(options_ptr, ":", &option_save_ptr);
		value_ptr = strtok_r(NULL, ";", &option_save_ptr);
		
		if(option_ptr == NULL || value_ptr == NULL)
		{
			return -1;
		}
		
		remove_char_from_str(option_buffer, option_ptr, ' ');
		remove_char_from_str(value_buffer, value_ptr, '"');

		if (strcmp(option_buffer, "msg") == 0)
		{
			strcpy(rule_ds->msg, value_buffer);
		}
		else if (strcmp(option_buffer, "content") == 0)
		{
			strcpy(rule_ds->content, value_buffer);
		}
		else
		{
			return -1;
		}
		
		options_ptr = strtok_r(NULL, ";", &options_save_ptr);
	}
	return 0;
}

int read_rules(FILE *rules_file, Rule *rules_ds, int count)
{
	int line_nb;
	int header_correctly_populate = -1;
    int option_correctly_populate = -1;
    char *option_ptr = NULL;
    char *header_ptr = NULL;
	char *saveptr = NULL;
    char *rule_line = NULL;
    size_t rule_line_len = 0;

    for(line_nb=0; line_nb<count; line_nb++)
    {
        getline(&rule_line, &rule_line_len, rules_file);
        
        header_ptr = strtok_r(rule_line, "(", &saveptr);
        option_ptr = strtok_r(NULL, ")", &saveptr);

        if (header_ptr == NULL || option_ptr == NULL)
        {
			return line_nb+1;
		}
        
        header_correctly_populate = populate_rule_header(header_ptr, &rules_ds[line_nb]);
        option_correctly_populate = populate_rule_option(option_ptr, &rules_ds[line_nb]);
         
        if (header_correctly_populate != 0 || option_correctly_populate != 0)
        {
			return line_nb+1;
		}
		
    }
    return 0;
}

bool rules_matcher(Rule *rules_ds, ETHER_Frame *frame)
{
	bool rule_header_match = false;
	bool ip_match = false;
	bool port_match = false;
	unsigned char *payload_ptr = NULL;

	// Header match	
	
	if (strcmp(frame->payload_protocol,"tcp") == 0 && strcmp(rules_ds->protocol,"tcp") == 0)
	{	
		ip_match = is_ip_match(rules_ds->ip_src, frame->ip_data.source_ip) && is_ip_match(rules_ds->ip_dst, frame->ip_data.destination_ip);
		port_match = is_port_match(rules_ds->port_src, frame->ip_data.tcp_data.source_port) && is_port_match(rules_ds->port_dst, frame->ip_data.tcp_data.destination_port);
		if(ip_match && port_match)
		{
			rule_header_match = true;
			payload_ptr = frame->ip_data.tcp_data.data;
		}
	}
	
	if (strcmp(rules_ds->protocol,"http") == 0)
	{
		if (strcmp(frame->payload_protocol,"http") == 0) 
		{
			ip_match = is_ip_match(rules_ds->ip_src, frame->ip_data.source_ip) && is_ip_match(rules_ds->ip_dst, frame->ip_data.destination_ip);
			port_match = is_port_match(rules_ds->port_src, frame->ip_data.tcp_data.source_port) && is_port_match(rules_ds->port_dst, frame->ip_data.tcp_data.destination_port);
			if(ip_match && port_match)
			{
				rule_header_match = true;
				payload_ptr = frame->ip_data.tcp_data.data;
			}
		}
		if (strcmp(frame->payload_protocol,"https") == 0)
		{
			ip_match = is_ip_match(rules_ds->ip_src, frame->ip_data.source_ip) && is_ip_match(rules_ds->ip_dst, frame->ip_data.destination_ip);
			rule_header_match = true;
		}
	}	
	if (strcmp(frame->payload_protocol,"ftp") == 0 && strcmp(rules_ds->protocol,"ftp") == 0)
	{	
				
		ip_match = is_ip_match(rules_ds->ip_src, frame->ip_data.source_ip) && is_ip_match(rules_ds->ip_dst, frame->ip_data.destination_ip);
		port_match = is_port_match(rules_ds->port_src, frame->ip_data.tcp_data.source_port) && is_port_match(rules_ds->port_dst, frame->ip_data.tcp_data.destination_port);
		if(ip_match && port_match)
		{
			rule_header_match = true;
			payload_ptr = frame->ip_data.tcp_data.data;
		}
	}	
	if (strcmp(frame->payload_protocol,"ssh") == 0 && strcmp(rules_ds->protocol,"ssh") == 0)
	{	
		ip_match = is_ip_match(rules_ds->ip_src, frame->ip_data.source_ip) && is_ip_match(rules_ds->ip_dst, frame->ip_data.destination_ip);
		port_match = is_port_match(rules_ds->port_src, frame->ip_data.tcp_data.source_port) && is_port_match(rules_ds->port_dst, frame->ip_data.tcp_data.destination_port);
		if(ip_match && port_match)
		{
			rule_header_match = true;
			payload_ptr = frame->ip_data.tcp_data.data;
		}
	}
	if(strcmp(frame->payload_protocol,"udp") == 0 && strcmp(rules_ds->protocol,"udp") == 0)
	{	
		ip_match = is_ip_match(rules_ds->ip_src, frame->ip_data.source_ip) && is_ip_match(rules_ds->ip_dst, frame->ip_data.destination_ip);
		port_match = is_port_match(rules_ds->port_src, frame->ip_data.tcp_data.source_port) && is_port_match(rules_ds->port_dst, frame->ip_data.tcp_data.destination_port);
		if(ip_match && port_match)
		{
			rule_header_match = true;
			payload_ptr = frame->ip_data.udp_data.data;
		}
	}
	if (strcmp(frame->payload_protocol,"icmp") == 0 && strcmp(rules_ds->protocol,"icmp") == 0)
	{
		ip_match = is_ip_match(rules_ds->ip_src, frame->ip_data.source_ip) && is_ip_match(rules_ds->ip_dst, frame->ip_data.destination_ip);
		if(ip_match)
		{
			rule_header_match = true;
		}
	}
		
	// Option(s) match	
	
	if (rule_header_match && strcmp(frame->payload_protocol, "https") == 0)
	{
		syslog(LOG_DEBUG, "HTTPS detected, can't afford content check ...");
		return true;
	}

	
	if (rule_header_match && strlen(rules_ds->content) > 0)
	{
		if (strstr((char*)payload_ptr, rules_ds->content))
		{
			syslog(LOG_DEBUG, rules_ds->msg);
			return true;
		}
	}
	
	if (rule_header_match == true && strlen(rules_ds->content) == 0)
	{
		syslog(LOG_DEBUG, rules_ds->msg);
		return true;				
	}
	
	return false;
}


void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	
	ETHER_Frame frame;
	Pcap_args *params;
	Rule *rules;
	int rules_total_nb;
	int frame_match_rules;
	int i;
	
	frame_match_rules = 0;
	params = (Pcap_args*) args;
	rules_total_nb = params->rules_counter;
	rules = params->rules_ptr;
	
	populate_packet_ds(header, packet, &frame);

	
	for (i=0; i<rules_total_nb && !frame_match_rules; i++)
	{
		frame_match_rules = rules_matcher(&rules[i], &frame);	
	}
	
	//check_syn_flood(struct packet_syn, &frame, header->ts.tv_sec)
}

int main(int argc, char *argv[])
{

    FILE *rules_file;
    Rule *rules;
    pcap_t * handle;
    
    char device[STR_MAX_SIZE];
    char err_msg[STR_MAX_SIZE];
    char error_buffer[PCAP_ERRBUF_SIZE];

    int rules_file_lines_count = 0;
    int error_in_line = -1;
    
    check_args_validity(argc, argv);
    assign_interface(argc, argv, device);
	printf("Interface sélectionné : %s\n", device);
	
    rules_file = fopen(argv[1], "r");
	if(rules_file == NULL)
    {
        print_error("le fichier rules n'existe pas");
        exit(EXIT_FAILURE);
    }
    
    rules_file_lines_count = count_file_lines(rules_file);
    rules = rules_malloc(rules_file_lines_count);
    printf("Nb de ligne dans le fichier %s : %d\n", argv[1], rules_file_lines_count);

    error_in_line = read_rules(rules_file, rules, rules_file_lines_count);
    if (error_in_line != 0)
    {
        sprintf(err_msg, "Erreur de configuration dans le fichier rules ligne %d", error_in_line);
        print_error(err_msg);
        exit(EXIT_FAILURE);
    }
    
    fclose(rules_file);
	print_rules(rules, rules_file_lines_count);

	handle = pcap_create(device, error_buffer);
    pcap_set_timeout(handle,10);
    pcap_activate(handle);
    int total_packet_count = -1;
    Pcap_args args = {rules_file_lines_count, rules};
    
    pcap_loop(handle, total_packet_count, (pcap_handler) my_packet_handler, (u_char *) &args); // doit aussi prendre le tableau de structure RULES
	free(rules);
    return EXIT_SUCCESS;
}
