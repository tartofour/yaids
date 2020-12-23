<h1 align="center">
  <a href="https://github.com/tartofour/yaids"><img src="https://cdn.freebiesupply.com/logos/large/2x/c-2975-logo-png-transparent.png" alt="Yaids" width="200"></a>
  <br>
  Projet de développement : Yaids (Yet Another IDS)
  <br>
  <br>
</h1>


## Table des Matières

- Démarrage rapide
    - [Dépendances](#d%C3%A9pendances)
    - [Installation](#installation)
    - [Utilisation](#utilisation)
    - [Protocoles pris en charge](#protocoles-pris-en-charge)
    - [Options de règles](#options-de-règles)
- Documentation du code source
    - **main.c**
		- [struct ids_rule](#struct-ids_rule)
		- [struct pcap_arguments](#struct-pcap-arguments)
		- [void print_help(char *prg_name);](#print-help)
		- [void print_error(char *err_str);](#print-error)
		- [void print_rules(Rule *rules, int count);](#print-rules)
		- [void initialize_http_message_struct(Http_msg message);](#initialize-http)
		- [void remove_char_from_str(char *new_str, char *str, char char_to_remove);](#remove-char)
		- [bool is_action_in_rules_valid(char *action_str);](#is-action)
		- [bool is_protocol_in_rules_valid(char *protocol);](#is-proto)
		- [bool is_ip_in_rules_valid(char *ip);](#is-ip-in-rules)
		- [bool is_port_in_rules_valid(char *port);](#is-port-in-rules)
		- [bool is_direction_in_rules_valid(char *direction);](#is-direction)
		- [bool is_ip_match(char* rules_ip, char* captured_ip);](#is-ip-match)
		- [bool is_port_match(int rule_port, int capture_port);](#is-port-match)
		- [void check_interface_validity(char *choosen_interface_name);](#check-interface)
		- [int check_args_validity(int argc, char * argv[]);](#check-args)
		- [void assign_default_interface(char *device);](#assign-default-int)
		- [void assign_interface(int argc, char *argv[], char *device);](#assign-int)
		- [int count_file_lines(FILE* file);](#count-lines)
		- [Rule* rules_malloc(int count);](#rules-malloc)
		- [int populate_rule_header(char *line, Rule *rule_ds);](#populate-header)
		- [int populate_rule_option(char *line, Rule *rule_ds);](#populate-option)
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
		- [struct custom_arp](#custom-arp)
		- [struct custom_ethernet](#custom-eth)

# Démarrage rapide
## Dépendances

Afin d'être en mesure de compiler le code source, le packet `libcap-dev` doit être installé sur la machine hôte.  
Pour install lib-cap:

```bash
# apt update && apt install -y libcap-dev
```

## Installation

La façon la plus facile d'installer yaids est de cloner ce dépôt et de compiler le code source à l'aide du fichier Makefile.  
Pour ce faire, exécutez les commandes suivantes depuis le terminal:

```
$ git clone https://github.com/tartofour/yaids.git
$ cd yaids
$ make
```

### Intégration au système GNU/Linux

Pour ajouter automatiquement `yaids` dans le dossier `/usr/local/bin/` et pour l'intégrer à systemd, executez le script d'installation en temps qu'administrateur:

```
# ./install.sh
```

## Désinstallation

Pour désinstaller yaids, executez le script de désinstallation en temps qu'administrateur:

```
# ./uninstall.sh
```

## Utilisation

Afin d'executer `yaids`, il est indispensable de lui fournir un fichier de règles.  
Il est également recommandé de spécifier une interface d'écoute :

```
# yaids <rules_file> [interface]
```

## Protocoles pris en charge

Permet de définir le protocole sur lequel s'applique la règle. `yaids` prend en charge les protocoles suivants:
- `TCP`
- `UDP`
- `ICMP`
- `HTTP`
- `FTP`
- `SSH`

## Options de règles
Yaids prend en charge deux type d'options :
- `content` qui permet de rechercher une chaine de caractère dans le payload d'un paquet.
- `msg` qui permet de définir la chaine de caractère à écrire dans le journal du système lors d'un match. 

# Documentation du code source
## main.c

#### <a name="struct-ids-rule">struct ids_rule</a>

```
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
	
} typedef Rule; 
```

Description : 
- Cette structure permet de stocker les différentes règles qui seront comparées aux paquets capturés par libpcap.

* * *

#### <a name="struct-pcap-arguments">struct pcap_arguments</a>


```
struct pcap_arguments
{
	int rules_counter;
	Rule *rules_ptr;
	
} typedef Pcap_args;
```

Description : 
- Cette structure permet de stocker des arguments supplémentaires à envoyer à my_packet_handler lors de l'appel à la fonction `pcap_loop`.
Pour faire fonctionner `my_packet_handler` correctement, nous avions besoin de lui fournir deux arguments supplémentaires depuis notre fonction main, à savoir un pointeur vers le tableau d'instance Rule et le nombre total de règles.
La fonction `pcap_loop` ne peut cependant prendre qu'un seul argument personnalisé.
Pour permettre d'envoyer les deux paramètres, nous avons décidé de créer une structure et d'utiliser cette structure comme argument.

* * * 


#### <a name="print-help">void print_help(char * prg_name);</a>

Description : 
- Affiche le menu d'aide.

Argument : 
- char * prg_name : Nom du programme
* * *

#### <a name="print-error">void print_error(char * err_str);</a>

Description :
- Affiche un message d'erreur.

Argument : 
- char * err_str: Chaine de caractère à afficher à l'écran
* * *

#### <a name="print-rules"> void print_rules(Rule *rules, int count);</a>

Description :
- Affiche un résumé des règles présentes dans le tableau de règles.

Argument : 
- Rule *rules : Tableau d'instances rules.
- int count : Nombre d'instances rules dans le tableau.

* * *

#### <a name="remove-char"> void remove_char_from_str(char *new_str, char *str, char char_to_remove);</a>

Description :
- Copie une chaine de caractère en retirant le caractère entré en paramètre.

Arguments : 
- char *new_str : Nouvelle chaine de caractère à remplir.
- char *str : Chaine de caractère à parcourir.
- char char_to_remove : Caractère à supprimer.

* * *

#### <a name="is-action">bool is_action_in_rule_valid(char *action);</a>
Description :

- Vérifie la validité de la valeur présente dans le champ `action` d'une ligne extraite du fichier de règle.

Argument : 
- char *action : Chaine de caractère à analyser.

* * *

#### <a name="is-proto">bool is_protocol_in_rules_valid(char *protocol);</a>

Description :
- Vérifie la validité de la valeur présente dans le champ `protocole` d'une ligne extraite du fichier de règle.

Argument : 
- char *protocol : Chaine de caractère à analyser

* * *

#### <a name="is-ip-in-rules">bool is_ip_in_rules_valid(char *ip);</a>

Description :
- Vérifie la validité de la valeur présente dans un des champs `ip` d'une ligne extraite du fichier de règle.

Argument : 
- char *ip : Chaine de caractère à analyser.
* * *

#### <a name="is-port-in-rules">bool is_port_in_rules_valid(char *port);</a>

Description :
- Vérifie la validité de la valeur présente dans un des champs `port` d'une ligne extraite du fichier de règle.

Argument : 
- char *port : Chaine de caractère à analyser

* * *

#### <a name="is-direction-in-rules">bool is_direction_in_rules_valid(char *direction);</a>

Description :
- Vérifie la validité de la valeur présente dans le champ `direction` d'une ligne extraite du fichier de règle.

Argument : 
- char *direction : Chaine de caractère à analyser.

* * *

#### <a name="is-ip-match">bool is_ip_match(char* rules_ip, char* captured_ip);</a>

Description :
- Compare une ip contenue dans une structure règle avec l'ip fournie en paramètre. 

Argument : 
- char* rules_ip : IP source ou destination stockée dans une structure règle.
- char* captured_ip : IP à comparer.

* * *

#### <a name="is-port-match">bool is_port_match(int rule_port, int capture_port);</a>

Description :
- Compare un port contenu dans une structure règle avec le port fourni en paramètre. Retourne vrai si les ports correspondent. 

Argument : 
- char* rules_port : Port source ou destination stocké dans une structure règle.
- int captured_port : Port à comparer.

* * * 

#### <a name="check-interface">void check_interface_validity(char *choosen_interface_name);</a>

Description :
- Vérifier que l'interface inséré en paramètre est bien présent sur la machine. 

Argument : 
- char* char *choosen_interface_name : Nom de l'interface à vérifier.

* * * 

#### <a name="check-args">int check_args_validity(int argc, char * argv[]);</a>

Description :
- Vérifier que les arguments entrés par l'utilisateur lors de l'execution du programme sont valides. 

Argument : 
- int argc : Nombre d'arguments.
- char * argv[] : Tableau chaine de caractère contenant les arguments.

* * * 

#### <a name="assign-default-int">void assign_default_interface(char *device);</a>

Description :
- Assigne l'interface réseau par défaut.

Argument : 
- char *device : Pointeur vers un chaine de caractère contenant le nom de l'interface qui utilisé par pcaplib lors de la capture.

* * * 

#### <a name="assign-int">void assign_interface(int argc, char *argv[], char *device);</a>

Description :
- Si aucun interface n'a été séléctionné par l'utilisateur, cette fonction assigne l'interface réseau par défaut. Si un interface à été séléctionné par l'utilisateur, elle vérifie que cette interface est valide en appelant la fonction check_interface_validity() avant de l'assigner.

Argument : 
- int argc : Nombre d'argument(s).
- char * argv[] : Tableau chaines de caractères contenant les arguments.
- char *device : Pointeur vers un chaine de caractère contenant le nom de l'interface utilisé par pcaplib lors de la capture.

* * * 

#### <a name="count-lines">Rule* rules_malloc(int count);</a>

Description :
- Réserve en mémoire l'espace nécessaire afin de stocker les différentes structures de règle. Initialise également ces structures.

Argument : 
- int count : Nombre de structure Rules à créer.

* * * 

#### <a name="populate-header">int populate_rule_header(char *line, Rule *rule_ds);</a>

Description :
- Divise une ligne du fichier de règle et remplit les champs d'entête d'une struture Rule avec les valeurs obtenues. La fonction vérifie que ces données soient bien valides avec de peupler la structure.

Arguments : 
- char *line : Ligne du fichier de règles à parcourir.
- Rule *rule_ds : structure Rule à peupler.

* * * 

#### <a name="populate-option">int populate_rule_option(char *line, Rule *rule_ds);</a>

Description :
- Divise une ligne du fichier de règle et remplit les champs d'option d'une struture Rule avec les valeurs obtenues. La fonction vérifie que ces données soient valides avec de peupler la structure.

Arguments : 
- char *line : Ligne du fichier de règles à parcourir.
- Rule *rule_ds : structure Rule à peupler.

* * * 

#### <a name="read-rules">int read_rules(FILE *rules_file, Rule *rules_ds, int count);</a>

Description :
- Parcours chaques lignes du fichier de régles et appel les fonctions `populate_rule_header()` et `populate_rule_option()` afin de peupler la structure Rule.

Arguments : 
- FILE *rules_file : Pointeur vers le fichier de règles déjà ouvert.
- Rule *rule_ds : Pointeur vers le tableau de structures Rule à peupler.
- int count : Nombre de ligne présentes dans le fichier de règles. 

* * * 

#### <a name="rules-matcher">bool rules_matcher(Rule *rules_ds, ETHER_Frame *frame);</a>

Description :
- Effectue la comparaison entre UNE règle et une trame ethernet.

Arguments : 
- Rule *rule_ds : Pointeur vers la structures Rule à comparer.
- ETHER_Frame *frame : Pointeur vers la structure custom_ethernet contenant la trame capturée.

* * * 

#### <a name="packet-handler">void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);</a>

Description :
- Fonction de callback systématiquement appelée lors de la capture d'une nouvelle trame par la fonction `pcap_loop`.

Arguments : 
- u_char *args : Pointeur vers une structures contenant les valeurs supplémentaire à in.
- ETHER_Frame *frame : Pointeur vers la structure custom_ethernet contenant la trame capturée.

* * * 

#### <a name="main">int main(int argc, char *argv[]);</a>
Description : 
- Fonction principalement permettant :
	- dddddd

* * *

## populate.c
#### <a name="generate-ip">void generate_ip(unsigned int ip, char ip_addr[]);</a>

Description :
- Permet de transormer un adresse ip de type u_int en chaine de caractère.

Arguments : 
- unsigned int ip : IP représenté avec le type entier.
- char ip_addr[] : Chaine de caractère à remplir après la conversion.

* * *

#### <a name="print-payload">void print_payload(int payload_length, unsigned char *payload);</a>

Description :
- Permet d'afficher le contenu du payload d'un packet.

Arguments : 
- int payload_length : Longueur du payload.
- unsigned char *payload : Pointeur vers le payload.

* * * 

#### <a name="print-ethernet-header">void print_ethernet_header(ETHER_Frame *frame);</a>

Description :
- Permet d'afficher le contenu d'un entête ethernet.

Arguments : 
- ETHER_Frame *frame : Pointeur vers une trame ethernet.

* * * 

#### <a name="print-ip-header">void print_ip_header(IP_Packet *packet);</a>

Description :
- Permet d'afficher le contenu d'un entête ip.

Arguments : 
- IP_Packet *packet : Pointeur vers un packet IP.

* * * 

#### <a name="print-tcp-header">void print_tcp_header(TCP_Segment *segment);</a>

Description :
- Permet d'afficher le contenu d'un entête TCP.

Arguments : 
- TCP_Segment *segment : Pointeur vers un segment TCP.

* * * 

#### <a name="print-udp-header">void print_udp_header(UDP_Datagram *datagram);</a>

Description :
- Permet d'afficher le contenu d'un entête UDP.

Arguments : 
- UDP_Datagram *datagram : Pointeur vers un datagramme UDP.

* * *

#### <a name="print-arp-header">void print_arp_header(ARP_Packet *packet);</a>

Description :
- Permet d'afficher le contenu d'un entête ARP.

Arguments : 
- ARP_Packet *packet : Pointeur vers un paquet ARP.

* * *

#### <a name="print-icmp-header">void print_icmp_header(ICMP_Msg *message);</a>

Description :
- Permet d'afficher le contenu d'un entête ICMP.

Arguments : 
- ICMP_Msg *message : Pointeur vers un message ICMP.

#### <a name="populate-packet-ds">int populate_packet_ds(const struct pcap_pkthdr *header, const u_char *packet, ETHER_Frame *custom_frame);</a>

Description :
- Permet de peupler une structure de type ETHER_Frame en fonction du packet capturé par pcaplib.

Arguments : 
- const struct pcap_pkthdr *header : Pointeur permettant d'accéder aux informations relatives au paquet brute capturé par pcaplib.
- const u_char *packet : Pointeur vers le paquet brute capturé par pcaplib.
- ETHER_Frame *custom_frame : Pointeur vers la structure custom_ethernet à peupler.

* * *

#### <a name="sniff-eth">struct sniff_ethernet</a>

 
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
