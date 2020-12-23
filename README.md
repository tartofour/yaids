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
    - [main.c](#main.c)
    - [populate.c](#populate.c)
    - [populate.h](#populate.h)
    
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
### void print_help(char * prg_name);

Description : 
- Affiche le menu d'aide.

Argument : 
- char * prg_name : Nom du programme
* * *

### void print_error(char * err_str)

Description :
- Affiche un message d'erreur.

Argument : 
- char * err_str: Chaine de caractère à afficher à l'écran
* * *

### void print_rules(Rule *rules, int count)

Description :
- Affiche un résumé des règles présentes dans le tableau de règles.

Argument : 
- Rule *rules : Tableau d'instances rules.
- int count : Nombre d'instances rules dans le tableau.

* * *

### void remove_char_from_str(char *new_str, char *str, char char_to_remove)

Description :
- Copie une chaine de caractère en retirant le caractère entré en paramètre.

Arguments : 
- char *new_str : Nouvelle chaine de caractère à remplir.
- char *str : Chaine de caractère à parcourir.
- char char_to_remove : Caractère à supprimer.

* * *

### bool is_action_in_rule_valid(char *action)
Description :

- Vérifie la validité de la valeur présente dans le champ `action` d'une ligne extraite du fichier de règle.

Argument : 
- char *action : Chaine de caractère à analyser.

* * *

#### bool is_protocol_in_rules_valid(char *protocol)

Description :
- Vérifie la validité de la valeur présente dans le champ `protocole` d'une ligne extraite du fichier de règle.

Argument : 
- char *protocol : Chaine de caractère à analyser

* * *

#### bool is_ip_in_rules_valid(char *ip)

Description :
- Vérifie la validité de la valeur présente dans un des champs `ip` d'une ligne extraite du fichier de règle.

Argument : 
- char *ip : Chaine de caractère à analyser.
* * *

### bool is_port_in_rules_valid(char *port)

Description :
- Vérifie la validité de la valeur présente dans un des champs `port` d'une ligne extraite du fichier de règle.

Argument : 
- char *port : Chaine de caractère à analyser

* * *

### bool is_direction_in_rules_valid(char *direction)

Description :
- Vérifie la validité de la valeur présente dans le champ `direction` d'une ligne extraite du fichier de règle.

Argument : 
- char *direction : Chaine de caractère à analyser.

* * *

### bool is_ip_match(char* rules_ip, char* captured_ip)

Description :
- Compare une ip contenue dans une structure règle avec l'ip fournie en paramètre. 

Argument : 
- char* rules_ip : IP source ou destination stockée dans une structure règle.
- char* captured_ip : IP à comparer.

* * *

### bool is_port_match(int rule_port, int capture_port)

Description :
- Compare un port contenu dans une structure règle avec le port fourni en paramètre. Retourne vrai si les ports correspondent. 

Argument : 
- char* rules_port : Port source ou destination stocké dans une structure règle.
- int captured_port : Port à comparer.

* * * 

### void check_interface_validity(char *choosen_interface_name)

Description :
- Vérifier que l'interface inséré en paramètre est bien présent sur la machine. 

Argument : 
- char* char *choosen_interface_name : Nom de l'interface à vérifier.

* * * 

### int check_args_validity(int argc, char * argv[])

Description :
- Vérifier que les arguments entrés par l'utilisateur lors de l'execution du programme sont valides. 

Argument : 
- int argc : Nombre d'arguments.
- char * argv[] : Tableau chaine de caractère contenant les arguments.

* * * 

### void assign_default_interface(char *device)

Description :
- Assigne l'interface réseau par défaut.

Argument : 
- char *device : Pointeur vers un chaine de caractère contenant le nom de l'interface qui utilisé par pcaplib lors de la capture.

* * * 

### void assign_interface(int argc, char *argv[], char *device)

Description :
- Si aucun interface n'a été séléctionné par l'utilisateur, cette fonction assigne l'interface réseau par défaut. Si un interface à été séléctionné par l'utilisateur, elle vérifie que cette interface est valide en appelant la fonction check_interface_validity() avant de l'assigner.

Argument : 
- int argc : Nombre d'argument(s).
- char * argv[] : Tableau chaines de caractères contenant les arguments.
- char *device : Pointeur vers un chaine de caractère contenant le nom de l'interface utilisé par pcaplib lors de la capture.

* * * 

### Rule* rules_malloc(int count)
Description :
- Réserve en mémoire l'espace nécessaire afin de stocker les différentes structures de règle. Initialise également ces structures.

Argument : 
- int count : Nombre de structure Rules à créer.

* * * 

### int populate_rule_header(char *line, Rule *rule_ds)



## Licence

[MIT](/usr/share/joplin/resources/app.asar/LICENSE "LICENSE"). Copyright (c) Jonathan Rasque & Benjamin Verjus
