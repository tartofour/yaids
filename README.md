<h1 align="center">
  <a href="https://github.com/tartofour/yaids"><img src="https://cdn.freebiesupply.com/logos/large/2x/c-2975-logo-png-transparent.png" alt="Yaids" width="200"></a>
  <br>
  Projet de développement : Yaids (Yet Another IDS)
  <br>
  <br>
</h1>


## Table des Matières

- Démarrage rapide
    - [Dépendances](#dependances)
    - [Installation](#installation)
    - [Lancement via le fichier exécutable](#lancement-via-le-fichier-executable)
	- [Intégration au système GNU/Linux](#integration-au-systeme-gnu/linux)
	- [Désinstallation](#desinstallation)
    - [Protocoles pris en charge](#protocoles-pris-en-charge)
    - [Options de règles](#options-de-règles)
    - [Exemple de fichier de règles](#exemple-de-fichier-de-règles)
- Documentation du code source
    - **main.c**
		- [struct ids_rule](#struct-ids_rule)
		- [struct pcap_arguments](#struct-pcap-arguments)
		- [Rule* rules_malloc(int count);](#rules-malloc)
		- [void print_help(char *prg_name);](#print-help)
		- [void print_error(char *err_str);](#print-error)
		- [void print_rules(Rule *rules, int count);](#print-rules)
		- [void remove_char_from_str(char *new_str, char *str, char char_to_remove);](#remove-char)
		- [bool is_action_in_rules_valid(char *action_str);](#is-action)
		- [bool is_protocol_in_rules_valid(char *protocol);](#is-proto)
		- [bool is_ip_in_rules_valid(char *ip);](#is-ip-in-rules)
		- [bool is_port_in_rules_valid(char *port);](#is-port-in-rules)
		- [bool is_direction_in_rules_valid(char *direction);](#is-direction-in-rules-valid)
		- [bool is_pcre_in_rules_valid(char *regex);](#is-pcre-in-rules-valid)
		- [bool is_ip_match(char* rules_ip, char* captured_ip);](#is-ip-match)
		- [bool is_port_match(int rule_port, int capture_port);](#is-port-match)
		- [void check_interface_validity(char *choosen_interface_name);](#check-interface)
		- [int check_args_validity(int argc, char * argv[]);](#check-args)
		- [void assign_default_interface(char *device);](#assign-default-int)
		- [void assign_interface(int argc, char *argv[], char *device);](#assign-int)
		- [int count_file_lines(FILE* file);](#count-file-lines)
		- [int populate_rule_header(char *line, Rule *rule_ds);](#populate-rule-header)
		- [int populate_rule_option(char *line, Rule *rule_ds);](#populate-rule-option)
		- [int read_rules(FILE *rules_file, Rule *rules_ds, int count);](#read-rules)
		- [bool rules_matcher(Rule *rules_ds, ETHER_Frame *frame);](#rules-matcher)
		- [void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);](#packet-handler)
		- [int main(int argc, char *argv[]);](#main)

    - **populate.c**
		- [void generate_ip(unsigned int ip, char ip_addr[]);](#generate-ip)
		- [void print_payload(int payload_length, unsigned char *payload);](#print-payload)
		- [void print_ethernet_header(ETHER_Frame *frame);](#print-ethernet-header)
		- [void print_ip_header(IP_Packet *packet);](#print-ip-header)
		- [void print_tcp_header(TCP_Segment *segment);](#print-tcp-header)
		- [void print_udp_header(UDP_Datagram *datagram);](#print-udp-header)
		- [void print_arp_header(ARP_Packet *packet);](#print-arp-header)
		- [void print_icmp_header(ICMP_Msg *message);](#print-icmp-header)
		- [int populate_packet_ds(const struct pcap_pkthdr *header, const u_char *packet, ETHER_Frame *custom_frame);](#populate-packet-ds)
    		
    - **populate.h**
		- [struct sniff_ethernet](#sniff-eth)
		- [struct sniff_arp](#sniff-arp)
		- [struct sniff_ip](#sniff-ip)
		- [struct sniff_icmp](#sniff-icmp)
		- [struct sniff_udp](#sniff-udp)
		- [struct sniff_tcp](#sniff-tcp)
		- [struct custom_icmp](#custom-icmp)
		- [struct custom_udp](#custom-udp)
		- [struct custom_tcp](#custom-tcp)
		- [struct custom_ip](#custom-ip)
		- [struct custom_ethernet](#custom-eth)

# Démarrage rapide
## <a name="dependances">Dépendances</a>

Afin d'être en mesure de compiler le code source, les paquets `libcap-dev`, `libpcre3-dev` doivent être installés sur la machine hôte. De plus, le paquet `git` est nécessaire pour cloner ce dépôt :

```bash
# apt update && apt install -y libcap-dev libpcre3-dev git
```

## <a name="installation">Installation</a>

La façon la plus facile d'installer yaids est de cloner ce dépôt et de compiler le code source à l'aide du fichier Makefile.  
Pour ce faire, exécutez les commandes suivantes depuis le terminal:

```
$ git clone https://github.com/tartofour/yaids.git
$ cd yaids
$ make
```

## <a name="lancement-via-le-fichier-executable">Lancement via le fichier exécutable</a>

Afin d'executer l'IDS, il est indispensable de lui fournir un fichier de règles.  
Il est également recommandé de spécifier une interface d'écoute :

```
# ./yaids <rules_file> [interface]
```

## <a name="integration-au-systeme-gnu/linux">Intégration au système GNU/Linux</a>

Pour ajouter automatiquement `yaids` dans le dossier `/usr/local/bin/` et pour l'intégrer à systemd, executez le script d'installation en tant qu'administrateur:

```
# ./install.sh
```
Une fois l'installation terminée, vous pouvez vérifier que le service `yaids` est bien en marche :

```
# systemctl status yaids.service
```
Il est possible de modifier les règles utilisées par l'IDS via le fichier `/etc/rules.txt`. Il est nécessaire de redémarrer le service `yaids` à chaque modification de ce fichier.

## <a name="desinstallation">Désinstallation</a>

Pour désinstaller yaids, executez le script de désinstallation en temps qu'administrateur:

```
# ./uninstall.sh
```

## <a name="protocoles-pris-en-charge">Protocoles pris en charge</a>

Permet de définir le protocole sur lequel s'applique la règle. `yaids` prend en charge les protocoles suivants:
- `TCP`
- `UDP`
- `ICMP`
- `HTTP`
- `FTP`
- `SSH`

##  <a name="options-de-regles">Options de règles</a>

Yaids prend en charge deux types d'options :
- `content` qui permet de rechercher une chaine de caractères dans le payload d'un paquet. Cette option est utilisable pour les protocoles `TCP`, `UDP` et `HTTP`.
- `pcre` qui permet de rechercher une expression régulière dans le payload d'un paquet. Cette option est utilisable pour les protocoles `TCP`, `UDP` et `HTTP`.
- `msg` qui permet de définir la chaine de caractères à écrire dans le journal du système lors d'un match. Cette option est utilisable pour tous les protocoles.

## <a name="exemple-de-fichier-de-règles">Exemple de fichier de règles </a>
``` bash
alert udp any any -> any 9999 (msg:"UDP traffic bind port is forbidden";)
alert http 192.168.56.102 any -> any any (msg:"XSS Attack detected"; pcre:"<script>alert.'[a-zA-Z]*'.<\/script>";)
alert http 192.168.56.102 any -> any any (msg:"Default page detected"; content:"Apache2 Debian Default Page";)
alert ssh 192.168.56.102 any -> any any (msg:"SSH connexion to critical server detected";)
alert ftp any any -> any any (msg:"Unsecure protocol use detected";)
alert tcp any any -> any 8888 (msg:"Backdoor attack";)
alert icmp any any -> 192.168.56.102 any (msg:"Ping to critical server detected";)
``` 

# Documentation du code source
## main.c

#### <a name="struct-ids-rule">struct ids_rule</a>
Description : 
- Cette structure permet de stocker une règle qui sera par la suite comparée aux paquets capturés par libpcap.

``` C
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
	char pcre[STR_MAX_SIZE];
	
} typedef Rule;
```

* * *

#### <a name="struct-pcap-arguments">struct pcap_arguments</a>

Description : 
- Cette structure permet de stocker des arguments supplémentaires à envoyer à la fonction `my_packet_handler` lors de l'appel de `pcap_loop`.

Choix d'implémentation :
- Pour faire fonctionner `my_packet_handler` correctement, nous avions besoin de lui fournir deux arguments à savoir un pointeur vers le tableau d'instance Rule et le nombre total de règles.
La fonction `pcap_loop` ne peut cependant prendre qu'un seul argument personnalisé.
Pour contourner ce problème, nous avons donc décidé de créer une structure contenant nos deux arguments et d'utiliser un pointeur vers cette structure comme argument pour `pcap_loop`.

``` C
struct pcap_arguments
{
	int rules_counter;
	Rule *rules_ptr;
	
} typedef Pcap_args;
```

* * * 

#### <a name="rules-malloc">Rule* rules_malloc(int count);</a>

Description :
- Réserve l'espace mémoire nécessaire au stockage des différentes structures `Rule` dans un tableau. La fonction initialise également les structures créées.

Argument : 
- `int count` : Nombre de structures Rules à créer.

Valeur de retour : 
- `Rule*` : Pointeur vers le début d'un tableau d'une ou plusieurs `Rule`.

Choix d'implémentation :
- Nous avons décidé d'initialiser la valeur des différents champs de nos structures `Rule` à l'aide de memset directement dans cette fonction. Celà nous permet d'éviter qu'il ne persiste des données parasites dans les différents champs des structures.

``` C
Rule* rules_malloc(int count)
{
	Rule* ptr = (Rule *) malloc(sizeof(Rule) * count);
	int i;
	
	for(i=0; i<count; i++)
	{
		memset(ptr->action, '\0', ACTION_LEN_STR);
		memset(ptr->protocol, '\0', PROTOCOL_LEN_STR);
		memset(ptr->ip_src, '\0', IP_ADDR_LEN_STR);
		memset(ptr->direction, '\0', DIRECTION_LEN_STR);
		memset(ptr->ip_dst, '\0', IP_ADDR_LEN_STR);
		memset(ptr->content, '\0', STR_MAX_SIZE);
		memset(ptr->msg, '\0', STR_MAX_SIZE);
		memset(ptr->pcre, '\0', STR_MAX_SIZE);
		ptr->port_src = -1;
		ptr->port_dst = -1;
	}
	return ptr;
}
```

* * * 

#### <a name="print-help">void print_help(char * prg_name);</a>

Description : 
- Affiche le menu d'aide.

Argument : 
- `char *prg_name` : Nom du programme

Choix d'implémentation :
- Le nom du programme passé en argument permet d'afficher à l'utilisateur la commande exacte à utiliser pour faire fonctionnr l'IDS, et ce même si le nom du fichier binaire a été modifié. Pour réaliser ce menu d'aide, nous nous sommes inspiré du menu d'aide de `snort`.

``` C
void print_help(char * prg_name)
{
	char *version = "1.201222";
	char *authors = "Jonathan Rasque & Benjamin Verjus";
	char *github_repo = "https://github.com/tartofour/yaids";
	char *pcap_version = "libpcap version 1.9.1";
	
	printf("\n   .-. \t\t-*> Yaids! <*-\n");
	printf("  (o o)\t\tVersion %s\n", version);
	printf("  | O \\\t\tBy %s\n", authors);
	printf("   \\   \\ \tGithub : %s\n", github_repo);
	printf("    `~~~' \tUsing libpcap version: %s\n\n", pcap_version);
	printf("USAGE : %s <rules_file> [interface]\n\n", prg_name);
	printf("OPTION : -h, display this message\n");
	printf("\n");
}
```
* * *

#### <a name="print-error">void print_error(char * err_str);</a>

Description :
- Affiche un message d'erreur sur la sortie standard d'erreur.

Argument : 
- `char *err_str` : Chaine de caractère à afficher à l'écran

Choix d'implémentation :
- Cette fonction nous permet de formater de manière homogène les erreurs obtenues lors de l'exécution du programme.

``` C
void print_error(char * err_str)
{
	fprintf(stderr, "Erreur : %s\n", err_str);
}
```

* * *

#### <a name="print-rules"> void print_rules(Rule *rules, int count);</a>

Description :
- Affiche un résumé des règles présentes dans le tableau de règles.

Argument : 
- `Rule *rules` : Tableau d'instances rules.
- `int count` : Nombre d'instances rules dans le tableau.

Choix d'implémentation :
- Cette fonction existe à des fins de débogage. 

``` C
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
		printf("Msg : %s\n", rules[i].msg);
		printf("Content : %s\n", rules[i].content);
		printf("PCRE : %s\n", rules[i].pcre);	
		printf("\n");
	}
}
```

* * *

#### <a name="remove-char"> void remove_char_from_str(char *new_str, char *str, char char_to_remove);</a>

Description :
- Copie une chaine de caractère en retirant le caractère entré en paramètre.

Arguments : 
- `char *new_str` : Nouvelle chaine de caractère à remplir.
- `char *str` : Chaine de caractère à parcourir.
- `char char_to_remove` : Caractère à supprimer.

Choix d'implémentation :
- Cette fonction nous a été utile à plusieurs reprises afin de "nettoyer" les chaines de caractères obtenues lors de la lecture du fichier de règles. Nous nous assurons de supprimer les caractères indésirables avant des les copier dans la structure de règle.

``` C
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
```

* * *

#### <a name="is-action">bool is_action_in_rule_valid(char *action);</a>
Description :

- Vérifie la validité de la valeur présente dans le champ `action` d'une ligne extraite du fichier de règles.

Argument : 
- `char *action` : Chaine de caractère à analyser.

Valeur de retour : 
- `true` ou `false`

```
bool is_action_in_rules_valid(char *action_str)
{
	if(strcmp(action_str, "alert") == 0)
	{   
		return true;
	}   
	return false;
}

```

* * *

#### <a name="is-proto">bool is_protocol_in_rules_valid(char *protocol);</a>

Description :
- Vérifie la validité de la valeur présente dans le champ `protocole` d'une ligne extraite du fichier de règles.

Argument : 
- `char *protocol` : Chaine de caractère à analyser

Valeur de retour : 
- `true` ou `false`

``` C
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
```

* * *

#### <a name="is-ip-in-rules">bool is_ip_in_rules_valid(char *ip);</a>

Description :
- Vérifie la validité de la valeur présente dans un des champs `ip` d'une ligne extraite du fichier de règles.

Argument : 
- `char *ip` : Chaine de caractère à analyser.

Valeur de retour : 
- `true` ou `false`

Choix d'implémentation :
- Pour cette fonction, nous avons utilisé une boucle qui parcourt chacun des champs de l'ip fournie en paramètre. Nous vérifions ainsi la validité de chaque octet de l'ip. De plus, la fonction vérifie que l'adresse ip est bien de constituée de 4 octets.

``` C
bool is_ip_in_rules_valid(char *ip)
{
	char ip_buffer[STR_MAX_SIZE];
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
```
* * *

#### <a name="is-port-in-rules">bool is_port_in_rules_valid(char *port);</a>

Description :
- Vérifie la validité de la valeur présente dans un des champs `port` d'une ligne extraite du fichier de règle.

Argument : 
- `char *port` : Chaine de caractère à analyser

Valeur de retour : 
- `true` ou `false`

``` C
bool is_port_in_rules_valid(char *port)
{	
	if (strcmp(port, "any") == 0 || (atoi(port) >= 1 && atoi(port) <= 65535))
	{
		return true;
	}  
	return false; 
}    
```

* * *

#### <a name="is-direction-in-rules-valid">bool is_direction_in_rules_valid(char *direction);</a>

Description :
- Vérifie la validité de la valeur présente dans le champ `direction` d'une ligne extraite du fichier de règle.

Argument : 
- `char *direction` : Chaine de caractère à analyser.

Valeur de retour : 
- `true` ou `false`

``` C
bool is_direction_in_rules_valid(char *direction)
{
	if(strcmp(direction, "->") == 0 || strcmp(direction, "<-") == 0)
	{
		return true;
	}	
	return false;
}
```
* * * 
#### <a name="is-pcre-in-rules-valid">bool is_pcre_in_rules_valid(char *regex);</a>

Description :
- Vérifie la validité de l'expression régulière présente dans le champ `pcre` d'une ligne extraite du fichier de règles. La fonction va tenter de compiler l'expression régulière pour déterminer si cette dernière est valide ou non.

Argument : 
- `char *regex` : Chaine de caractère à analyser.

Valeur de retour:
- `true` : L'expression régulière compile correctement.
- `false` : La compilation échoue.

``` C
bool is_pcre_in_rules_valid(char *regex)
{
	pcre *compiled_pcre = NULL;
	const char *error ;
	int error_offset;
	
	compiled_pcre = pcre_compile(regex, 0, &error, &error_offset, NULL);
	if (compiled_pcre == NULL)
	{
		pcre_free(compiled_pcre);
		return false;
	}
	pcre_free(compiled_pcre);
	return true;
}
```

* * *

#### <a name="is-ip-match">bool is_ip_match(char* rules_ip, char* captured_ip);</a>

Description :
- Permet de comparer deux IP.

Argument : 
- `char *rules_ip` : IP source ou destination stockée dans une structure règle.
- `char *captured_ip` : IP à comparer.

Valeur de retour:
- `true` si les ip correspondent.
- `false` si les ip ne correspondent pas.

``` C
bool is_ip_match(char* rules_ip, char* captured_ip)
{
	if (strcmp(rules_ip, "any") == 0 || strcmp(rules_ip, captured_ip) == 0)
	{
		return true;
	}
	return false;
}
```

* * *

#### <a name="is-port-match">bool is_port_match(int rule_port, int capture_port);</a>

Description :
- Permet de comparer un port venant d'une structure règle avec un port venant d'une structure eternet_custom. Retourne vrai si les ports correspondent. 

Argument : 
- `char *rules_port` : Port source ou destination stocké dans une structure règle.
- `int captured_port` : Port à comparer.

Valeur de retour:
- `true` si les ports correspondent.
- `false` si les ports ne correspondent pas.

``` C
bool is_port_match(int rule_port, int capture_port)
{
	if (rule_port == 0 || rule_port == capture_port)
	{
		return true;
	}
	return false;
}
```

* * * 

#### <a name="check-interface">void check_interface_validity(char *choosen_interface_name);</a>

Description :
- Vérifie que l'interface réseau choisi par l'utilisateur est bien présent sur la machine. Dans le cas contraire, le programme se ferme en retournant une erreur sur la sortie standard d'erreur. Le code de cette fonction est inspiré des examples présents dans la documentation de la librairie `ifaddrs`.

Argument : 
- `char *choosen_interface_name` : Nom de l'interface à vérifier.

``` C
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
```

* * * 

#### <a name="check-args">int check_args_validity(int argc, char * argv[]);</a>

Description :
- Vérifie que les arguments entrés par l'utilisateur lors de l'exécution du programme sont valides. Dans le cas contraire, ferme le programme en retournant un message d'erreur sur la sortie standard d'erreur.

Arguments : 
- `int argc` : Nombre d'arguments.
- `char * argv[]` : Tableau chaine de caractère contenant les arguments.

``` C
void check_args_validity(int argc, char * argv[])
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
}
```

* * * 

#### <a name="assign-default-int">void assign_default_interface(char *device);</a>

Description :
- Assigne l'interface réseau par défaut.

Argument : 
- `char *device` : Pointeur vers un chaine de caractère contenant le nom de l'interface qui utilisé par pcaplib lors de la capture. Cette fonction permet de rendre facultative la sélection d'un interface réseau par l'utilisateur lors du lancement du programme.

``` C
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
```

* * * 

#### <a name="assign-int">void assign_interface(int argc, char *argv[], char *device);</a>

Description :
- Si aucun interface n'a été séléctionné par l'utilisateur lors du démarrage du programme, cette fonction assigne l'interface réseau par défaut. Si un interface a été séléctionné par l'utilisateur, elle vérifie que cet interface est valide en appelant la fonction `check_interface_validity()` avant de l'assigner.

Argument : 
- `int argc` : Nombre d'argument(s).
- `char * argv[]` : Tableau chaines de caractères contenant les arguments.
- `char *device` : Pointeur vers un chaine de caractère contenant le nom de l'interface utilisé par pcaplib lors de la capture.

``` C
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
```
* * * 

#### <a name="count-file-lines">int count_file_lines(FILE* file);</a>

Description :
- Parcourt un fichier et compte le nombre de lignes qui y sont présentes. 

Arguments : 
- FILE* : Le fichier déjà ouvert à parcourir.

Valeur de retour :
- Nombre de lignes dans le fichier de règles.

``` C
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
```
* * * 

#### <a name="populate-rule-header">int populate_rule_header(char *line, Rule *rule_ds);</a>

Description :
- Divise une ligne du fichier de règles et remplit les `champs d'entête` d'une struture `Rule` avec les valeurs obtenues. La fonction vérifie que ces données sont bien valides avec de garnir la structure.

Arguments : 
- `char *line` : Ligne du fichier de règles à parcourir.
- `Rule *rule_ds` : structure Rule à garnir.

Valeur de retour:
- 0 si le "peuplage" de l'entête a réussi.
- -1 en cas d'erreur.

``` C
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
```

* * * 

#### <a name="populate-rule-option">int populate_rule_option(char *line, Rule *rule_ds);</a>

Description :
- Divise une ligne du fichier de règles et remplit les `champs d'option` d'une struture `Rule` avec les valeurs obtenues. La fonction vérifie que ces données sont bien valides avec de garnir la structure.

Arguments : 
- `char *line` : Ligne du fichier de règles à parcourir.
- `Rule *rule_ds` : structure Rule à garnir.

Valeur de retour:
- 0 si le "peuplage" des options a réussi.
- -1 en cas d'erreur.

``` C
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
			if(strcmp(rule_ds->protocol, "ftp") == 0 || strcmp(rule_ds->protocol, "ssh") == 0 || strcmp(rule_ds->protocol, "icmp") == 0)
			{
				return -1;
			}
			strcpy(rule_ds->content, value_buffer);
		}
		else if (strcmp(option_buffer, "pcre") == 0)
		{
			if(strcmp(rule_ds->protocol, "ftp") == 0 || strcmp(rule_ds->protocol, "ssh") == 0 || strcmp(rule_ds->protocol, "icmp") == 0 || !is_pcre_in_rules_valid(value_buffer))
			{
				return -1;
			}	
			strcpy(rule_ds->pcre, value_buffer);
		}
		else
		{
			return -1;
		}
		
		options_ptr = strtok_r(NULL, ";", &options_save_ptr);
	}
	return 0;
}
```

* * * 

#### <a name="read-rules">int read_rules(FILE *rules_file, Rule *rules_ds, int count);</a>

Description :
- Parcourt chaque ligne du fichier de régles et appelle les fonctions `populate_rule_header()` et `populate_rule_option()` afin de garnir une structure `Rule`.

Arguments : 
- `FILE *rules_file` : Pointeur vers le fichier de règles déjà ouvert.
- `Rule *rule_ds` : Pointeur vers le tableau de structures Rule à peupler.
- `int count` : Nombre de ligne présentes dans le fichier de règles. 

Valeur de retour : 
- `0` si le "peuplage" se déroule sans erreur.
- `line_nb+1` en cas d'erreur. Cette valeur représente le numéro de la ligne où l'erreur a été détectée dans un format "human readable" (on commence à compter par 1).

``` C
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
```

* * * 

#### <a name="rules-matcher">bool rules_matcher(Rule *rules_ds, ETHER_Frame *frame);</a>

Description :
- Effectue la comparaison entre UNE règle et une trame ethernet.

Arguments : 
- `Rule *rule_ds` : Pointeur vers la structures Rule à comparer.
- `ETHER_Frame *frame` : Pointeur vers la structure custom_ethernet contenant la trame capturée.

Valeur de retour : 
- `true` : La règle et les informations contenue dans la trame correspondent (match)
- `false` : La règle et les informations contenue dans la trame ne correspondent pas (no match)

Choix d'implémentation : 
- Dans un premier temps, cette fonction vérifie la correspondance entre les champs d'entête d'une règle `Rule` et les informations contenues dans une trame `ETHER_Frame`.
- S'il y a correspondance, elle compare la trame `ETHER_Frame` avec les champs d'option de la règle. 
- En fonction de ces options, un message Syslog est généré ou non.

``` C
bool rules_matcher(Rule *rules_ds, ETHER_Frame *frame)
{
	bool rule_header_match = false;
	bool ip_match = false;
	bool port_match = false;
	u_char *payload_ptr = NULL;
	
	pcre *regex;
	int regex_result;
	const char *regex_err;
	int regex_err_offset;
	int ovector[OVECCOUNT];

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
		port_match = is_port_match(rules_ds->port_src, frame->ip_data.udp_data.source_port) && is_port_match(rules_ds->port_dst, frame->ip_data.udp_data.destination_port);

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
		syslog(LOG_DEBUG, "HTTPS detected...");
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
	
	if (rule_header_match && strlen(rules_ds->pcre) > 0)
	{
		regex = pcre_compile(rules_ds->pcre, 0, &regex_err, &regex_err_offset, NULL);
		regex_result = pcre_exec(regex, NULL, (char*)payload_ptr, strlen((char*)payload_ptr), 0, 0, ovector, OVECCOUNT);	
		
		if (regex_result < 0)
		{
			pcre_free(regex);
			return false;
		}
		syslog(LOG_DEBUG, rules_ds->msg);
		pcre_free(regex);
		return true;
	}	
	if (rule_header_match && strlen(rules_ds->content) == 0 && strlen(rules_ds->pcre) == 0)
	{
		syslog(LOG_DEBUG, rules_ds->msg);
		return true;				
	}
	return false;
}

```

* * * 

#### <a name="packet-handler">void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);</a>

Description :
- Fonction de callback systématiquement appelée lors de la capture d'un nouveau paquet par la fonction `pcap_loop`. Cette fonction garnit une structure ETHER_Frame avant de la comparer avec chacune des règles `Rule` présente dans notre tableau de règles.

Arguments : 
- `u_char *args` : Pointeur vers une structures contenant le pointeur vers le tableau de règles et le nombre de règles.
- `ETHER_Frame *frame` : Pointeur vers la structure custom_ethernet contenant la trame capturée.

``` C
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
}
```

* * * 

#### <a name="main">int main(int argc, char *argv[]);</a>
Description : 
- Fonction principale qui, dans l'ordre :
	- Vérifie que les arguments entrés au démarrage du programme sont corrects.
	- Assigne l'interface réseau adéquat.
	- Vérifie l'existance du fichier de règles et compte le nombre de lignes.
	- Alloue l'espace nécessaire au stockage des règles dans un tableau.
	- Crée le `pcap_handler` et appelle la fonction `pcap_loop`.
	- Libération de l'espace assigné au tableau de règles.

``` C
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
	//printf("Interface sélectionné : %s\n", device);
	
	rules_file = fopen(argv[1], "r");
	if(rules_file == NULL)
	{
		print_error("le fichier rules n'existe pas");
		exit(EXIT_FAILURE);
	}
	
	rules_file_lines_count = count_file_lines(rules_file);
	rules = rules_malloc(rules_file_lines_count);
	//printf("Nb de ligne dans le fichier %s : %d\n", argv[1], rules_file_lines_count);

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
```

* * *

## populate.c
#### <a name="generate-ip">void generate_ip(unsigned int ip, char ip_addr[]);</a>

Description :
- Transforme une adresse ip de type u_int en chaine de caractère.

Arguments : 
- `unsigned int ip` : IP représenté avec le type entier.
- `char ip_addr[]` : Chaine de caractère à remplir après la conversion.

``` C
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
```

* * *

#### <a name="print-payload">void print_payload(int payload_length, unsigned char *payload);</a>

Description :
- Affiche le contenu du payload d'un packet.

Arguments : 
- `int payload_length` : Longueur du payload.
- `unsigned char *payload` : Pointeur vers le payload.

``` C
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
```

* * * 

#### <a name="print-ethernet-header">void print_ethernet_header(ETHER_Frame *frame);</a>

Description :
- Afficher le contenu d'un entête ethernet.

Arguments : 
- `ETHER_Frame *frame` : Pointeur vers une trame ethernet.

``` C
void print_ethernet_header(ETHER_Frame *frame)
{
    printf("Source MAC : %s\n", frame->source_mac);
	printf("Destination MAC : %s\n", frame->source_mac);
    printf("Ethertype : %d\n", frame->ethertype);
    printf("\n");
}
```

* * * 

#### <a name="print-ip-header">void print_ip_header(IP_Packet *packet);</a>

Description :
- Affiche le contenu d'un entête ip.

Arguments : 
- `IP_Packet *packet` : Pointeur vers un packet IP.

``` C
void print_ip_header(IP_Packet *packet)
{
    printf("Source IP : %s\n", packet->source_ip);
	printf("Destination IP : %s\n", packet->destination_ip);
    printf("Layer 4 protocol : %d\n", packet->protocol);
    printf("\n");
}
```

* * * 

#### <a name="print-tcp-header">void print_tcp_header(TCP_Segment *segment);</a>

Description :
- Affiche le contenu d'un entête TCP.

Arguments : 
- `TCP_Segment *segment` : Pointeur vers un segment TCP.

``` C
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
```

* * * 

#### <a name="print-udp-header">void print_udp_header(UDP_Datagram *datagram);</a>

Description :
- Affiche le contenu d'un entête UDP.

Arguments : 
- `UDP_Datagram *datagram` : Pointeur vers un datagramme UDP.

``` C
void print_udp_header(UDP_Datagram *datagram)
{
    printf("Source Port : %d\n", datagram->source_port);
	printf("Destination Port : %d\n", datagram->destination_port);
    printf("Data Length : %d\n", datagram->data_length);
    printf("\n");
}
```

* * *

#### <a name="print-icmp-header">void print_icmp_header(ICMP_Msg *message);</a>

Description :
- Affiche le contenu d'un entête ICMP.

Arguments : 
- `ICMP_Msg *message` : Pointeur vers un message ICMP.

``` C
void print_icmp_header(ICMP_Msg *message)
{
    printf("Type : %d\n", message->type);
    printf("Code : %d\n", message->code);
	printf("ID : %d\n", message->id);
	printf("Sequence : %d\n", message->sequence);
	printf("\n");
}	
```

* * * 

#### <a name="populate-packet-ds">int populate_packet_ds(const struct pcap_pkthdr *header, const u_char *packet, ETHER_Frame *custom_frame);</a>

Description :
- Permet de garnir une structure de type ETHER_Frame en fonction de la trame capturée par pcaplib. 

Arguments : 
- `const struct pcap_pkthdr *header` : Pointeur permettant d'accéder aux informations relatives au paquet brute capturé par pcaplib.
- `const u_char *packet` : Pointeur vers le paquet brute capturé par pcaplib.
- `ETHER_Frame *custom_frame` : Pointeur vers la structure custom_ethernet à peupler.

``` C
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
	{       snprintf(src_mac_address+(x*2),ETHER_ADDR_LEN_STR,
					"%02x",ethernet->ether_shost[x]);
			snprintf(dst_mac_address+(x*2),ETHER_ADDR_LEN_STR,
					"%02x",ethernet->ether_dhost[x]);
	}

	strcpy(custom_frame->source_mac,src_mac_address);
	strcpy(custom_frame->destination_mac, dst_mac_address);
	custom_frame->frame_size = header->caplen;
	custom_frame->ethertype = ethernet->ether_type;
	//print_ethernet_header(custom_frame);
   
	// ARP
	
	if(ntohs(ethernet->ether_type) == ETHERTYPE_ARP) 
	{
		printf("--------------\n");
		printf("ARP packet: %d\n",custom_frame->ethertype);	
		
		custom_frame->ethertype = ARP;
		
		//arp = (struct sniff_arp*)(packet + SIZE_ETHERNET);
		//ARP_Packet custom_arp_packet;
		   
		strcpy(custom_frame->payload_protocol, "arp");
		
		//print_ethernet_header(ethernet);

	}
		
		//IP
	if(ntohs(ethernet->ether_type) == ETHERTYPE_IP) 
	{
		printf("--------------\n");
		printf("IPV4 packet: %d\n",custom_frame->ethertype);

		custom_frame->ethertype = IPV4;
		
		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
		IP_Packet custom_packet;
	   
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
			printf("ICMP Handling\n");

			icmp = (struct sniff_icmp*)(packet + SIZE_ETHERNET + size_ip);
			ICMP_Msg custom_icmp_msg;
			
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
			
			printf("UDP Handling\n");
			udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);	
			UDP_Datagram custom_udp_packet;				
			
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
			printf("TCP Handling\n");
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
```

* * *

#### <a name="sniff-eth">struct sniff_ethernet</a>
Description :
- Structure permettant de stocker les informations de l'entête Ethernet lors du cast d'une trame ethernet capturé par pcaploop.
 
``` C
struct sniff_ethernet 
{
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

```

* * *

#### <a name="sniff-arp">struct sniff_arp</a>
Description :
- Structure permettant de stocker les informations de l'entête ARP lors du cast d'un paquet ARP capturé par pcaploop.

``` C
struct sniff_arp {
	u_short arp_htype;
	u_short arp_ptype;
	u_char arp_hlen;
	u_char arp_plen;
	u_short arp_operation;
	u_char arp_src[ETHER_ADDR_LEN];
	u_char arp_src_proto_addr[4];
	u_char arp_dst[ETHER_ADDR_LEN];
	u_char arp_dst_proto_addr[4];
};

```
* * *

#### <a name="sniff-ip">struct sniff_ip</a>

Description :
- Structure permettant de stocker les informations de l'entête IP lors du cast d'un paquet IP capturé par pcaploop.

``` C
struct sniff_ip
{
	u_char ip_vhl;          /* version << 4 | header length >> 2 */
	u_char ip_tos;          /* type of service */
	u_short ip_len;         /* total length */
	u_short ip_id;          /* identification */
	u_short ip_off;         /* fragment offset field */
	#define IP_RF 0x8000            /* reserved fragment flag */
	#define IP_DF 0x4000            /* don't fragment flag */
	#define IP_MF 0x2000            /* more fragments flag */
	#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
	u_char ip_ttl;          /* time to live */
	u_char ip_p;            /* protocol */
	u_short ip_sum;         /* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};

```
* * *

#### <a name="sniff-icmp">struct sniff_icmp</a>

Description :
- Structure permettant de stocker les informations de l'entête ICMP lors du cast d'un message ICMP capturé par pcaploop.

``` C
struct sniff_icmp 
{
    u_char icmp_type;
	#define ICMP_ECHO 0x8
	#define ICMP_REPLY 0x0
    u_char icmp_code;
    u_int16_t icmp_sum;
    u_int16_t icmp_id;
	u_int16_t icmp_sequence;
};

```

* * *

#### <a name="sniff-udp">struct sniff_udp</a>

Description :
- Structure permettant de stocker les informations de l'entête UDP lors du cast d'un datagramme UDP capturé par pcaploop.

``` C
struct sniff_udp {
	u_short uh_sport;       /* source port */
	u_short uh_dport;       /* destination port */
	u_short uh_ulen;        /* udp length */
	u_short uh_sum;         /* udp checksum */
};

```

* * *

#### <a name="sniff-tcp">struct sniff_tcp</a>

Description :
- Structure permettant de stocker les informations de l'entête TCP lors du cast d'un segment TCP capturé par pcaploop.

``` C
#define IP_HL(ip)   (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)    (((ip)->ip_vhl) >> 4)
typedef u_int tcp_seq;
struct sniff_tcp {
        u_short th_sport;       /* source port */
        u_short th_dport;       /* destination port */
        tcp_seq th_seq;         /* sequence number */
        tcp_seq th_ack;         /* acknowledgement number */
        u_char th_offx2;        /* data offset, rsvd */
        #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
        #define TH_FIN 0x01
        #define TH_SYN 0x02
        #define TH_RST 0x04
        #define TH_PUSH 0x08
        #define TH_ACK 0x10
        #define TH_URG 0x20
        #define TH_ECE 0x40
        #define TH_CWR 0x80
        #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;         /* window */
        u_short th_sum;         /* checksum */
        u_short th_urp;         /* urgent pointer */
};

```

* * *

#### <a name="custom-icmp">struct custom_icmp</a>

Description :
- Structure personnalisée permettant de stocker un message ICMP dans un format facilement utilisable dans le reste du programme.

``` C
struct custom_icmp
{
	int type;
	int code;
	int id;
	int sequence;

} typedef ICMP_Msg;

```

* * *

#### <a name="custom-udp">struct custom_udp</a>

Description :
- Structure personnalisée permettant de stocker un datagramme UDP dans un format facilement utilisable dans le reste du programme.

``` C
struct custom_udp
{
	int source_port;
	int destination_port;
	unsigned char *data;
	int data_length;

} typedef UDP_Datagram;

```

* * *

#### <a name="custom-tcp">struct custom_tcp</a>

Description :
- Structure personnalisée permettant de stocker un segment TCP dans un format facilement utilisable dans le reste du programme.

``` C
struct custom_tcp
{
	int source_port;
	int destination_port;
	unsigned char *data;
	int data_length;

} typedef UDP_Datagram;

```
* * *

#### <a name="custom-ip">struct custom_ip</a>

Description :
- Structure personnalisée permettant de stocker un paquet IP dans un format facilement utilisable dans le reste du programme.

``` C
struct custom_ip
{
	char source_ip[IP_ADDR_LEN_STR];
	char destination_ip[IP_ADDR_LEN_STR];
	int protocol;
	TCP_Segment tcp_data;
	UDP_Datagram udp_data;
	ICMP_Msg icmp_data;

} typedef IP_Packet;

```

* * *

#### <a name="custom-arp">struct custom_arp</a>
Description :
- Structure personnalisée permettant de stocker un packet ARP dans un format facilement utilisable dans le reste du programme.

``` C
struct custom_arp
{
	int hw_type;
	int proto_layer3;
	int hw_addr_len;
	int proto_layer3_addr_len;
	int operation;
	u_char source_mac[6];
	u_char source_proto_addr[4];
	u_char arp_dst[6];
	u_char arp_dst_proto_addr[4];
} typedef ARP_Packet;


```
* * *

#### <a name="custom-eth">struct custom_ethernet</a>
Description :
- Structure personnalisée permettant de stocker une trâme Ethernet dans un format facilement utilisable dans le reste du programme. Elle comprend également le protocole utilisé par le payload applicatif ou, à défaut, son protocole de couche 4.
- 

``` C
struct custom_ethernet
{
        char source_mac[ETHER_ADDR_LEN_STR];
        char destination_mac[ETHER_ADDR_LEN_STR];
        char payload_protocol[PAYLOAD_PROTOCOL_LEN_STR];
        int ethertype;
        int frame_size;
        IP_Packet ip_data;
        ARP_Packet arp_data;

} typedef ETHER_Frame;

```

## Licence

[MIT](/usr/share/joplin/resources/app.asar/LICENSE "LICENSE"). Copyright (c) Jonathan Rasque & Benjamin Verjus
