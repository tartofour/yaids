/*TODO : 
Gérer les erreurs pour les ports dans le fichier rules
Enlever les guillemets -> remove_char_from_str('"', str_token);


*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <errno.h>
#include <stdbool.h>
#include "populate.h"

#define ACTION_LEN_STR 14
#define PROTOCOLE_LEN_STR 15
#define IP_ADDR_LEN_STR 16
#define DIRECTION_LEN_STR 3

#define STR_MAX_SIZE 255
#define ARGS_MAX_SIZE 255


struct ids_rule_options
{
    char content[STR_MAX_SIZE];
    char msg[STR_MAX_SIZE];

} typedef Rule_options;

struct ids_rule
{
    char action[ACTION_LEN_STR];
    char protocole[PROTOCOLE_LEN_STR];
    char ip_src[IP_ADDR_LEN_STR];
    int port_src;
    char direction[DIRECTION_LEN_STR];
    char ip_dst[IP_ADDR_LEN_STR];
    int port_dst;
    Rule_options options;
    
} typedef Rule;

struct pcap_arguments
{
	int rules_counter;
	Rule *rules_ptr;
} typedef Pcap_args;




void print_help(char * prg_name)
{
    printf("Utilisation : ");
    printf("%s interface rules_file\n", prg_name);
    printf("Écoute le traffic sur une interface réseau et ajoute une entrée dans syslog lors de la détection d'une activité dont la signature correspond avec une ou plusieurs règles définies dans le ficher rules_file.\n");
    printf("    -h,           affiche ce message\n");
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
		printf("msg : %s\n", rules[i].options.msg);
		printf("content : %s\n", rules[i].options.content);
		printf("\n");
    }
}

bool is_action_valid(char *action_str)
{
    if(strcmp(action_str, "alert") == 0)
    {   
        return true;
    }   
    return false;
}

bool is_protocole_valid(char *protocole)
{
	if(strcmp(protocole, "http") == 0 ||
		strcmp(protocole, "tcp") == 0 ||
		strcmp(protocole, "udp") == 0 ||
		strcmp(protocole, "icmp") == 0 ||
		strcmp(protocole, "ftp") == 0)
		
		return true;
		
	return false;
}

bool is_ip_valid(char *ip)
{
	char *saveptr;
	char *endptr;
	char *str_token = strtok_r(ip, ".", &saveptr);
	int ip_byte;
	int byte_nb = 0;
	
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

bool is_port_valid(char *port)
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

bool is_direction_valid(char *direction)
{
	if(strcmp(direction, "->") == 0 || strcmp(direction, "<-") == 0)
	{
		return true;
	}	
	
	return false;
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

    if (argc != 3)
    {
        print_error("nombre d'arguments invalides");
        exit(EXIT_FAILURE);
    }

    if (strlen(argv[1]+1) > ARGS_MAX_SIZE || strlen(argv[2]+1) > ARGS_MAX_SIZE)
    {
        print_error("limite de caractères dépassée par un ou plusieurs arguments");
        exit(EXIT_FAILURE);
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
    return ptr;
}

int populate_rule_header(char *line, char *delim, Rule *rule_ds)
{
    char *str_token;
    char *saveptr;
    int i;
   
    char ip_src[IP_ADDR_LEN_STR];
    char ip_dst[IP_ADDR_LEN_STR];
    
    

    str_token = strtok_r(line, delim, &saveptr);

    for (i=0; str_token != NULL; i++)
    {
        //printf("ici : %d - %s\n", i, str_token);
        switch (i)
        {
            case 0: 
				
				if(!is_action_valid(str_token))
				{
					return EXIT_FAILURE;
				}
					
                strcpy(rule_ds->action, str_token);
                break;

            case 1:
            
				if(!is_protocole_valid(str_token))
				{
					return EXIT_FAILURE;
				}
				
				strcpy(rule_ds->protocole, str_token);
				break;
				
                
            case 2:
            
				strcpy(ip_src, str_token);
            
				if (!is_ip_valid(ip_src))
                {
					return EXIT_FAILURE;
				}
				
                strcpy(rule_ds->ip_src, str_token);
                break;
                
            case 3: 
                
                if (!is_port_valid(str_token))
                {
					return EXIT_FAILURE;
				}
				
				rule_ds->port_src = atoi(str_token);
                break;

            case 4:
                        
				if(!is_direction_valid(str_token))
				{
					return EXIT_FAILURE;
                }
                
                strcpy(rule_ds->direction, str_token);
				break;

            case 5: // bool is_ip_valid()
            
            	strcpy(ip_dst, str_token);
                
				if (!is_ip_valid(ip_dst))
                {
					return EXIT_FAILURE;
				}
				
                strcpy(rule_ds->ip_dst, str_token);
                break;
                
            case 6: // bool is_port_valid()
				if (!is_port_valid(str_token))
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
    //printf("  \n");
    return EXIT_SUCCESS;
}

int populate_rule_option(char *line, char *delim, Rule *rule_ds)
{
    char *str_token;
    char *saveptr;
    int i;

    //printf("line : %s\n", line);
    str_token = strtok_r(line, delim, &saveptr);
    rule_ds->options.msg[0] = '\0';	
	rule_ds->options.content[0] = '\0';

    for (i=0; str_token != NULL; i++)
    {
		
		
        if (strcmp(str_token, "msg") == 0 || strcmp(str_token, " msg") == 0)
        {
            str_token = strtok_r(NULL, delim, &saveptr);
            strcpy(rule_ds->options.msg, str_token);
            //printf("msg : %s\n", rule_ds->options.msg);
            //remove_char_from_str('"', str_token);
           
        }

        else if (strcmp(str_token, " content") == 0 || strcmp(str_token, "content") == 0)
        {
            str_token = strtok_r(NULL, delim, &saveptr);
            //printf("%s\n", str_token);
            strcpy(rule_ds->options.content, str_token);
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

int rules_matcher(Rule *rules_ds, ETHER_Frame *frame)
{
	printf("Protocole : %d\n", frame->data.protocole);
    printf("IP src captured: %s\n", frame->data.source_ip);
    printf("IP src rules: %s\n", rules_ds->ip_src);
    printf("Port src captured: %d\n", frame->data.data.source_port);
    printf("Port src rules: %d\n", rules_ds->port_src);
    printf("IP dst captured: %s\n", frame->data.destination_ip);
    printf("IP dst rules: %s\n", rules_ds->ip_dst);
    printf("Port dst captured: %d\n", frame->data.data.destination_port);
    printf("Port dst rules: %d\n", rules_ds->port_dst);
    printf("content : %s\n", rules_ds->options.content);
    if (rules_ds->options.content[0] == '\0')
		printf("content est vide\n");
    printf("msg : %s\n", rules_ds->options.msg);
    if (rules_ds->options.msg[0] == '\0')
		printf("msg est vide\n");
    printf("---\n");
 
    //est-ce que le protocole du packet correspond au protocole de la ligne
   /* 
    
    if (strcmp(rules_ds->protocole, "udp") == 0
    {
		
	} 
	
	if (strcmp(rules_ds->protocole, "tcp") == 0
    {
		
	} 
	
	if (strcmp(rules_ds->protocole, "icmp") == 0
    {
		
	} 
	
	
	*/
	
	
	
   
    
    // source IP comparison
	if (strcmp(rules_ds->ip_src, "any") != 0 && 
		strcmp(rules_ds->ip_src, frame->data.source_ip) != 0)
	{
		return 0;
	}
	
	// source port comparison
	if (rules_ds->port_src != 0 && 
		rules_ds->port_src != frame->data.data.source_port)
	{
		return 0;
	}
	
	// destination IP comparison
	if (strcmp(rules_ds->ip_dst, "any") != 0 && 
		strcmp(rules_ds->ip_dst, frame->data.destination_ip) != 0)
	{
		return 0;
	}
  
	// source port comparison
	if (rules_ds->port_dst != 0 && 
		rules_ds->port_dst != frame->data.data.destination_port)
	{
		return 0;
	}
  
	// content and paylod comparison
	//if (rules_ds->options.content[0] != '\0')
	//	if 
	
	printf("SYSLOG : %s\n", rules_ds->options.msg);
	return 1;

  
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

}

int main(int argc, char *argv[])
{

    FILE *rules_file;
    Rule *rules;
    char *device;
    int rules_file_lines_count;
    char err_msg[STR_MAX_SIZE];
    int error_in_line;
    pcap_t * handle;
	char error_buffer[PCAP_ERRBUF_SIZE];


    check_args_validity(argc, argv);
    check_interface_validity(argv[1]);

    rules_file = fopen(argv[2], "r");
    check_rules_file(rules_file);
    rules_file_lines_count = count_file_lines(rules_file);
    printf("Compteur de line : %d\n", rules_file_lines_count);
    rules = rules_malloc(rules_file_lines_count);

    error_in_line = read_rules(rules_file, rules, rules_file_lines_count);
    if (error_in_line != 0)
    {
        sprintf(err_msg, "Erreur de configuration dans le fichier rules ligne %d", error_in_line);
        print_error(err_msg);
        exit(EXIT_FAILURE);
    }
    
    fclose(rules_file);
    //print_rules(rules, rules_file_lines_count);

	device = argv[1];
	
	handle = pcap_create(device, error_buffer);
    pcap_set_timeout(handle,10);
    pcap_activate(handle);
    int total_packet_count = 3;
    Pcap_args args = {rules_file_lines_count, rules};
    
    pcap_loop(handle, total_packet_count, (pcap_handler) my_packet_handler, (u_char *) &args); // doit aussi prendre le tableau de structure RULES
	free(rules);
    return EXIT_SUCCESS;
}
