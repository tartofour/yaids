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
#define PROTOCOLE_LEN_STR 15
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
    char protocole[PROTOCOLE_LEN_STR];
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
		printf("action : %s\n", rules[i].action);
		printf("protocole : %s\n", rules[i].protocole);
		printf("ip_src : %s\n", rules[i].ip_src);
		printf("port_src : %d\n", rules[i].port_src);
		printf("direction : %s\n", rules[i].direction);
		printf("ip_dst : %s\n", rules[i].ip_dst);
		printf("port_dst : %d\n", rules[i].port_dst);
		printf("msg : %s\n", rules[i].msg);
		printf("content : %s\n", rules[i].content);
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
	memset(rule->action, 0, ACTION_LEN_STR);
	memset(rule->protocole, 0, PROTOCOLE_LEN_STR);
	memset(rule->ip_src, 0, IP_ADDR_LEN_STR);
	memset(rule->direction, 0, DIRECTION_LEN_STR);
	memset(rule->ip_dst, 0, IP_ADDR_LEN_STR);
	memset(rule->content, 0, STR_MAX_SIZE);
	memset(rule->msg, 0, STR_MAX_SIZE);
	rule->port_src = -1;
	rule->port_dst = -1;
	//rule->count = -1;
	//rule->seconds = -1;
}

void remove_char_from_str(char char_to_remove, char *str, char *new_str)
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
	
}

bool is_action_in_rules_valid(char *action_str)
{
    if(strcmp(action_str, "alert") == 0)
    {   
        return true;
    }   
    return false;
}

bool is_protocole_in_rules_valid(char *protocole)
{
	if(strcmp(protocole, "http") == 0 ||
		strcmp(protocole, "tcp") == 0 ||
		strcmp(protocole, "udp") == 0 ||
		strcmp(protocole, "icmp") == 0 ||
		strcmp(protocole, "ssh") == 0 ||
		strcmp(protocole, "ftp") == 0)
		
		return true;
		
	return false;
}

bool is_ip_in_rules_valid(char *ip)
{
	char *str_token;
	char *saveptr;
	char *endptr;
	
	int ip_byte;
	int byte_nb;
	
	str_token = strtok_r(ip, ".", &saveptr);
	byte_nb = 0;
	
	if(strcmp(ip, "any") == 0)
	{
		return true;
	}

	while (str_token != NULL)
	{
		
		ip_byte = strtol(str_token, &endptr, 10);
		
		if(*endptr != '\0')
		{
			return false;
		}
		
		if (ip_byte < 0 || ip_byte > 255)
		{
			return false;
		}
		
		byte_nb++;
		str_token = strtok_r(NULL, ".", &saveptr);
	}
	
	if(byte_nb != 4)
	{
		return false;
	}
	
	return true;	
}

bool is_port_in_rules_valid(char *port)
{	
	if (strcmp(port, "any") == 0)
	{
		return true;
	}
	
	if (atoi(port) >= 1 && atoi(port) <= 65535)
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
	if (strcmp(rules_ip, "any") == 0)
	{
		return true;
	}
	
	if (strcmp(rules_ip, captured_ip) == 0)
	{
		return true;
	}
	
	return false;
}

bool is_port_match(int rule_port, int capture_port)
{
	if (rule_port == 0)
	{
		return true;
	}
	
	if (rule_port == capture_port)
	{
		return true;
	}
	
	return false;
}

int get_http_msg_type(char *http_status)
{
	char *str_token;
	str_token = strtok(http_status, " ");
	
	// Request
	if (strcmp(str_token, "GET") == 0 ||
		strcmp(str_token, "HEAD") == 0 ||
		strcmp(str_token, "POST") == 0 ||
		strcmp(str_token, "PUT") == 0 ||
		strcmp(str_token, "DELETE") == 0 ||
		strcmp(str_token, "CONNECT") == 0 ||
		strcmp(str_token, "OPTIONS") == 0 ||
		strcmp(str_token, "TRACE") == 0 ||
		strcmp(str_token, "PATCH") == 0)
	{
		return 1;
	}
	
	// Response
	else if (strcmp(str_token, "HTTP/1.1") == 0 ||
		strcmp(str_token, "HTTP/1.2") == 0 ||
		strcmp(str_token, "HTTP/2") == 0)
	{
		return 2;
	}
	
	return 0;
	
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

void check_rules_file(FILE* rules_file)
{
    if(rules_file == NULL)
    {
        print_error("le fichier rules n'existe pas");
        exit(EXIT_FAILURE);
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
		initialize_rule_struct(&ptr[i]);
	}
	
    return ptr;
}


void set_http_basic_info(char * first_http_line, Http_msg *http_msg)
{
	char *str_token;
	
	str_token = strtok(first_http_line, " ");
	
	// Request
	if (strcmp(str_token, "GET") == 0 ||
		strcmp(str_token, "HEAD") == 0 ||
		strcmp(str_token, "POST") == 0 ||
		strcmp(str_token, "PUT") == 0 ||
		strcmp(str_token, "DELETE") == 0 ||
		strcmp(str_token, "CONNECT") == 0 ||
		strcmp(str_token, "OPTIONS") == 0 ||
		strcmp(str_token, "TRACE") == 0 ||
		strcmp(str_token, "PATCH") == 0)
	{
		strcpy(http_msg->msg_type, "request");
		strcpy(http_msg->method, str_token);
		
		str_token = strtok(NULL, " ");
		str_token = strtok(NULL, " ");
		strcpy(http_msg->version, str_token);
		
	/*	
		printf("Type : %s\n", http_msg->msg_type);
		printf("HTTP version : %s\n", http_msg->version);
		
	*/	
	}
	
	// Response
	else if (strcmp(str_token, "HTTP/1.1") == 0 ||
		strcmp(str_token, "HTTP/1.2") == 0 ||
		strcmp(str_token, "HTTP/2") == 0)
	{
		strcpy(http_msg->msg_type, "response");
		strcpy(http_msg->version, str_token);
		str_token = strtok(NULL, " ");
		http_msg->status = atoi(str_token);
		
	/*
		printf("Type : %s\n", http_msg->msg_type);
		printf("HTTP version : %s\n", http_msg->version);
		printf("Status code : %d\n", http_msg->status);
	*/
	}
}

void populate_http_msg(unsigned char *msg_captured, Http_msg *http_msg)
{
	
	char *msg_line;
    char *msg_line_save_ptr;
    char *key;
    char *key_save_ptr;
    char *html = NULL;
    char *delim = "\r\n\r\n";

	
	html = strstr((char*)msg_captured, delim);
	
	
    if (html != NULL)
	{
		html[0] = '\0';
		//printf("Header:\n\n%s\n\n", msg_captured);
		//printf("HTML:\n\n%s\n\n", html+strlen(delim));
		http_msg->body = (u_char*)html+strlen(delim);
	}
    
    msg_line = strtok_r((char*)msg_captured, "\r", &msg_line_save_ptr);
 	
 	printf("msg : line %s", msg_line);
    set_http_basic_info(msg_line, http_msg);
    
    
    msg_line = strtok_r(NULL, "\n", &msg_line_save_ptr);  
       
    while(msg_line != NULL)
    {
		key = strtok_r(msg_line, ":", &key_save_ptr);
		
		if (key != NULL)
		{
			if (strcmp(key, "Host") == 0)
			{
				key = strtok_r(NULL, ":", &key_save_ptr);
				//printf("Host : %s\n", key);
				strcpy(http_msg->host, key);
			}
			
			else if (strcmp(key, "Content-Encoding") == 0)
			{
				key = strtok_r(NULL, ":", &key_save_ptr);
				//printf("Encoding : %s\n", key);
				strcpy(http_msg->encoding, key);
				
			}
			
			else if (strcmp(key, "Content-Length") == 0)
			{
				key = strtok_r(NULL, ":", &key_save_ptr);
				//printf("content len : %d\n", atoi(key));
				http_msg->body_len = atoi(key);
			}
			
			else if (strcmp(key, "Content-Type") == 0)
			{
				key = strtok_r(NULL, ":", &key_save_ptr);
				//printf("Content type : %s\n", key);
				strcpy(http_msg->content_type, key);
			}	
			
			else
			{
				key = strtok_r(NULL, ":", &key_save_ptr);
			}
			
			msg_line = strtok_r(NULL, "\n", &msg_line_save_ptr);
		}
	}
}



int populate_rule_header(char *line, char *delim, Rule *rule_ds)
{
    char ip_src[IP_ADDR_LEN_STR];
    char ip_dst[IP_ADDR_LEN_STR];
    char *str_token;
    char *saveptr;
    int i;
    
    str_token = strtok_r(line, delim, &saveptr);

    for (i=0; str_token != NULL; i++)
    {
        //printf(" : %d - %s\n", i, str_token);
        switch (i)
        {
            case 0: // Action
				
				if(!is_action_in_rules_valid(str_token))
				{
					return EXIT_FAILURE;
				}	
                strcpy(rule_ds->action, str_token);
                break;

            case 1: // Protocole
            
				if(!is_protocole_in_rules_valid(str_token))
				{
					return EXIT_FAILURE;
				}
				strcpy(rule_ds->protocole, str_token);
				break;		
                
            case 2: // IP Source
            
				strcpy(ip_src, str_token);
            
				if (!is_ip_in_rules_valid(ip_src))
                {
					return EXIT_FAILURE;
				}
                strcpy(rule_ds->ip_src, str_token);
                break;
                
            case 3:  // Port Source
                
                if (!is_port_in_rules_valid(str_token))
                {
					return EXIT_FAILURE;
				}
				rule_ds->port_src = atoi(str_token);
                break;

            case 4: // Direction
                        
				if(!is_direction_in_rules_valid(str_token))
				{
					return EXIT_FAILURE;
                }
                strcpy(rule_ds->direction, str_token);
				break;

            case 5: // IP Destination
            
            	strcpy(ip_dst, str_token);
                
				if (!is_ip_in_rules_valid(ip_dst))
                {
					return EXIT_FAILURE;
				}
                strcpy(rule_ds->ip_dst, str_token);
                break;
                
            case 6: // Port Destination
            
				if (!is_port_in_rules_valid(str_token))
                {
					return EXIT_FAILURE;
				}
				rule_ds->port_dst = atoi(str_token);
                break;

            default:
                return EXIT_FAILURE;
        }
        str_token = strtok_r(NULL, delim, &saveptr);

    }
    return EXIT_SUCCESS;
}

int populate_rule_option(char *line, char *delim, Rule *rule_ds)
{
    char key[STR_MAX_SIZE] = "";
    char item[STR_MAX_SIZE] = "";    
    
    char *str_token;
    char *saveptr;
    int i;
	
	str_token = strtok_r(line, delim, &saveptr);
		 
    for (i=0; str_token != NULL; i++)
    {
		memset(item, 0, STR_MAX_SIZE);
		memset(key, 0, STR_MAX_SIZE);
		remove_char_from_str(' ', str_token, key);
		
		
        if (strcmp(key, "msg") == 0)
        {
            str_token = strtok_r(NULL, delim, &saveptr);
            remove_char_from_str('"', str_token, item);
            strcpy(rule_ds->msg, item);
            //printf("msg : %s\n", rule_ds->msg); 
        }

        else if (strcmp(key, "content") == 0)
        {
            str_token = strtok_r(NULL, delim, &saveptr);
            remove_char_from_str('"', str_token, item);
            strcpy(rule_ds->content, item);
            //printf("content : %s\n", rule_ds->content);
        }
        /*
        else if (strcmp(key, "count") == 0)
        {
            str_token = strtok_r(NULL, delim, &saveptr);
            remove_char_from_str('"', str_token, item);
            rule_ds->count = atoi(item);
            //printf("content : %s\n", rule_ds->content);
        }
        
        else if (strcmp(key, "seconds") == 0)
        {
            str_token = strtok_r(NULL, delim, &saveptr);
            remove_char_from_str('"', str_token, item);
            rule_ds->secondes = atoi(item);
            //printf("content : %s\n", rule_ds->content);
        }
		*/
        else
        {
            return EXIT_FAILURE;
        }


        str_token = strtok_r(NULL, ";:", &saveptr);
    }
    return EXIT_SUCCESS;
}

int read_rules(FILE *rules_file, Rule *rules_ds, int count)
{

    char *line = NULL;
    char *line_cpy;
    int i;
    int rule_part;
    size_t len = 0;
    int line_nb = 1;

    for (i=0; i<count; i++)
    {
        getline(&line, &len, rules_file);
        line_cpy = line;
        int error = 0;
        rule_part = 0;

        //split de la ligne par les parenthèses
        char *rule_delim = "(";
        char *rule_header_delim = " ";
        char *rule_option_delim = ";:";
        char rule_header_line[512];
        char rule_option_line[512];
        char *saveptr;

        char *str_token = strtok_r(line_cpy, rule_delim, &saveptr);
        

        while (str_token != NULL)
        {

            if (rule_part == 0)
            {
                strcpy(rule_header_line, str_token);
                error = populate_rule_header(rule_header_line, rule_header_delim, &rules_ds[i]);
            }

            else if (rule_part == 1)
            {
                strcpy(rule_option_line, str_token);

                char * parenthese_in_line = strchr(rule_option_line,')');
                *parenthese_in_line = '\0';
                error = populate_rule_option(rule_option_line, rule_option_delim, &rules_ds[i]);
            }

            else
            {
                error = 1;
            }

            if (error)
            {
                return line_nb;
            }

            rule_part++;
            str_token = strtok_r(NULL, rule_delim, &saveptr);
        }
        line_nb++;
    }
    return EXIT_SUCCESS;
}

bool rules_matcher(Rule *rules_ds, ETHER_Frame *frame)
{
	Http_msg http_msg;
	u_char *udp_payload_buffer;
	u_char *tcp_payload_buffer;
	char *http_first_line = NULL;
			
	if (frame->ethernet_type == ETHERTYPE_IP)
    {
		
		if(!is_ip_match(rules_ds->ip_src, frame->ip_data.source_ip) ||
		   !is_ip_match(rules_ds->ip_dst, frame->ip_data.destination_ip))
		{
			return false;
		}
		
		if (frame->ip_data.protocole == ICMP_PROTOCOL)
		{
			if (strcmp(rules_ds->protocole, "icmp") == 0)
			{
				printf("Syslog\n");
				syslog(LOG_DEBUG, rules_ds->msg);
				return true;
			}
		} 
		
		if (frame->ip_data.protocole == UDP_PROTOCOL)
		{
			
			if (!is_port_match(rules_ds->port_src, frame->ip_data.udp_data.source_port) ||
				!is_port_match(rules_ds->port_dst, frame->ip_data.udp_data.destination_port))
			{
				return false;
			}
			
			udp_payload_buffer = (u_char *)malloc(sizeof(u_char)*frame->ip_data.udp_data.data_length);

			if (strcmp(rules_ds->protocole, "udp") == 0)
			{
				printf("UDP Rule Handling\n");

				if (rules_ds->content[0] == '\0')
				{	
					syslog(LOG_DEBUG, rules_ds->msg);
					free(udp_payload_buffer);
					return true;
				}
				
				
				if (frame->ip_data.udp_data.data_length > 0)
				{				
					if (strstr((char*)frame->ip_data.udp_data.data, rules_ds->content) != NULL)
					{
						// check encryption
						printf("Syslog\n");
						free(udp_payload_buffer);
						syslog(LOG_DEBUG, rules_ds->msg);
						return true;
					}
					
					free(udp_payload_buffer);
					return false;
				}		
			}
		free(udp_payload_buffer);} 

		if (frame->ip_data.protocole == TCP_PROTOCOL)
		{
			tcp_payload_buffer = (u_char *)malloc(sizeof(u_char)*frame->ip_data.tcp_data.data_length);
		
			if (!is_port_match(rules_ds->port_dst, frame->ip_data.tcp_data.source_port) ||
				!is_port_match(rules_ds->port_src, frame->ip_data.tcp_data.source_port))
			{
				free(tcp_payload_buffer);
				return false;
			}
		
		
			if (strcmp(rules_ds->protocole, "tcp") == 0)
			{
				printf("TCP Rule Handling\n");

				//printf("TCP data len : %d\n", frame->ip_data.tcp_data.data_length);
				
				
				if (rules_ds->content[0] == '\0')
				{	
					syslog(LOG_DEBUG, rules_ds->msg);
					free(tcp_payload_buffer);
					return true;
				}
				
				
				if (frame->ip_data.tcp_data.data_length > 0)
				{
					if (strstr((char*)frame->ip_data.tcp_data.data, rules_ds->content) != NULL)

					{
						printf("Syslog\n");
						syslog(LOG_DEBUG, rules_ds->msg);
						free(tcp_payload_buffer);

						return true;
					}
					
					//check encryption
					free(tcp_payload_buffer);
					return false;
				}
			}
			
			if (strcmp(rules_ds->protocole, "ftp") == 0)
			{
				printf("FTP Rule Handling\n");
				//printf("data !!! : %s", frame->ip_data.tcp_data.data);
				if (strstr((char*)frame->ip_data.tcp_data.data, "230 Login successful.\r\n") != NULL)
				{
					printf("Syslog\n");
					syslog(LOG_DEBUG, rules_ds->msg);
					free(tcp_payload_buffer);
					return true;	
				}
			}
			
			if (strcmp(rules_ds->protocole, "ssh") == 0)
			{		
				printf("SSH Rule Handling\n");
		
				if (strstr((char*)frame->ip_data.tcp_data.data, "SSH") != NULL)
				{
					printf("Syslog\n");
					syslog(LOG_DEBUG, rules_ds->msg);
					free(tcp_payload_buffer);
					return true;
				}
			}
			
			if (strcmp(rules_ds->protocole, "http") == 0)
			
			{
				printf("HTTP Rules Handling\n");
				/*
				initialize_http_message_struct(http_msg);
				
				
				http_first_line = strtok((char*)tcp_payload_buffer, "\n");
				
				
				if (strstr((char *)frame->ip_data.tcp_data.data, "HTTP/") != NULL)
				{
					if (rules_ds->content[0] == '\0')
					{
						syslog(LOG_DEBUG, rules_ds->msg);
						free(tcp_payload_buffer);
						return true;				
					}
					
					//populate_http_msg(tcp_payload_buffer, &http_msg);
					
					printf("data : %s", (char*)http_msg.body);

					if (strstr((char*)http_msg.body, rules_ds->content) != NULL)
						{
							syslog(LOG_DEBUG, rules_ds->msg);
							free(tcp_payload_buffer);
							return true;
						}	
						
					if (strstr((char*)http_msg.body, rules_ds->content) != NULL)
					{
						syslog(LOG_DEBUG, rules_ds->msg);
						free(tcp_payload_buffer);
						return true;
					}
					
					if (http_msg.encoding[0] == '\0')			
					{
						if (strstr((char*)http_msg.body, rules_ds->content) != NULL)
						{
							syslog(LOG_DEBUG, rules_ds->content);
							
							free(tcp_payload_buffer);
							return true;
						}
					}
					
					if (strcmp(http_msg.encoding, " gzip\r") == 0)			
					{
						printf("Http body is compressed with gzip, unable to read");
						syslog(LOG_DEBUG, "Http body is compressed with gzip, unable to read");
						free(tcp_payload_buffer);
						return true;
						//http_decoded_body = gzip_decode(http_msg.response.body);
					}
						
				}*/
				
			}
		free(tcp_payload_buffer);
		return false;}
	}
	
	if (frame->ethernet_type == ETHERTYPE_ARP)	
	{
		
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
		printf("Rule n°%d\n", i);
		frame_match_rules = rules_matcher(&rules[i], &frame);
		
	}
	//printf("Payload tcp length : %d\n", frame.ip_data.udp_data.data_length);
	//printf("Payload ucp length : %d\n", frame.ip_data.tcp_data.data_length);

	

	//print_payload(frame.ip_data.tcp_data.data_length , frame.ip_data.tcp_data.data); // test tcp
	//print_payload(frame.ip_data.udp_data.data_length , frame.ip_data.udp_data.data); // test tcp

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
    check_rules_file(rules_file);
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
    //print_rules(rules, rules_file_lines_count);
	
	handle = pcap_create(device, error_buffer);
    pcap_set_timeout(handle,10);
    pcap_activate(handle);
    int total_packet_count = -1;
    Pcap_args args = {rules_file_lines_count, rules};
    
    pcap_loop(handle, total_packet_count, (pcap_handler) my_packet_handler, (u_char *) &args); // doit aussi prendre le tableau de structure RULES
	free(rules);
    return EXIT_SUCCESS;
}
