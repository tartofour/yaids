/* TODO : 
 * 	- TCP SYN attack
 * 		- creer un tableau de structure syn_packets qui contient l'ip src,
 * 		  ip dest, et me nb de syn capturé pour ces ip.
 * 		- realloc le tableau à chaque paquet TCP syn qui entre
 * 		- define un threshold
 * 
 * 	- Comment détecter si payload chiffré ?
 * 				
 */	



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <errno.h>
#include <stdbool.h>
#include <syslog.h>
#include "populate.h"

#define ACTION_LEN_STR 14
#define PROTOCOLE_LEN_STR 15
#define IP_ADDR_LEN_STR 16
#define DIRECTION_LEN_STR 3

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
    
} typedef Rule;

struct pcap_arguments
{
	int rules_counter;
	Rule *rules_ptr;
	
} typedef Pcap_args;

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

char* detect_udp_payload_protocol(int payload_length, unsigned char *payload)
{
 	//is_protocole_http()
	//is_protocole_ftp()
}

char *detect_tcp_payload_protocol(int payload_length, unsigned char *payload)
{
	//is_protocole_http()
	//is_protocole_ftp()
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
		memset(ptr->action, 0, ACTION_LEN_STR);
		memset(ptr->protocole, 0, PROTOCOLE_LEN_STR);
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
            printf("msg : %s\n", rule_ds->msg); 
        }

        else if (strcmp(key, "content") == 0)
        {
            str_token = strtok_r(NULL, delim, &saveptr);
            remove_char_from_str('"', str_token, item);
            strcpy(rule_ds->content, item);
            printf("content : %s\n", rule_ds->content);
        }

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
	printf("Rules matcher start\n");
	
	
	if (frame->ethernet_type == ETHERTYPE_IP)
    {
		printf("Eternet type IP\n");
		
		if(!is_ip_match(rules_ds->ip_src, frame->ip_data.source_ip) ||
		   !is_ip_match(rules_ds->ip_dst, frame->ip_data.destination_ip))
		{
			return false;
		}
		
	
	/*	
		if (frame->ip_data.protocole == ICMP_PROTOCOL)
		{
			syslog(LOG_DEBUG, rules_ds->msg);

		} 

		
		if (frame->ip_data.protocole == UDP_PROTOCOL)
			
		{
			if (!is_port_match(rules_ds->port_src, frame->ip_data.udp_data.source_port) ||
				!is_port_match(rules_ds->port_dst, frame->ip_data.udp_data.destination_port))
			{
				return;
			}
			
			char *payload_protocol = detect_udp_payload_protocol(frame->ip_data.udp_data.data_length, frame->ip_data.udp_data.data);

			if (strcmp(rules_ds->protocole, "udp") != 0 &&
				strcmp(rules_ds->protocole, payload_protocol) != 0)
				
			{
				return;
			}
			
			syslog(LOG_DEBUG, rules_ds->msg);
	
		} 
*/
		if (frame->ip_data.protocole == TCP_PROTOCOL)
		{
		
			if (!is_port_match(rules_ds->port_dst, frame->ip_data.tcp_data.source_port) ||
				!is_port_match(rules_ds->port_src, frame->ip_data.tcp_data.source_port))
			{
				return false;
			}
		
			if (strcmp(rules_ds->protocole, "tcp") == 0)
			{
				printf("Syslog\n");
				syslog(LOG_DEBUG, rules_ds->msg);
				return true;
			}
	
		/*	char *payload_protocol = detect_tcp_payload_protocol(frame->ip_data.tcp_data.data_length, frame->ip_data.tcp_data.data);


			if strcmp(rules_ds->protocole, payload_protocol) != 0)
				
			{
				printf("Syslog\n");
				syslog(LOG_DEBUG, rules_ds->msg);
				return true;
			}
			
			
		*/
		}
		
	}
	
	/*	
	if (frame->ethernet_type == ETHERTYPE_ARP)	
	 
	{

	} 
	*/


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
		printf("Rule n° %d\n", i);
		frame_match_rules = rules_matcher(&rules[i], &frame);
		
	}
	//check_syn_flood(struct packet_syn, &frame)

}

int main(int argc, char *argv[])
{

    FILE *rules_file;
    Rule *rules;
    pcap_t * handle;
    
    char device[STR_MAX_SIZE];
    char err_msg[STR_MAX_SIZE];
    char error_buffer[PCAP_ERRBUF_SIZE];

    int rules_file_lines_count;
    int error_in_line;
    
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
    int total_packet_count = 1;
    Pcap_args args = {rules_file_lines_count, rules};
    
    pcap_loop(handle, total_packet_count, (pcap_handler) my_packet_handler, (u_char *) &args); // doit aussi prendre le tableau de structure RULES
	free(rules);
    return EXIT_SUCCESS;
}
